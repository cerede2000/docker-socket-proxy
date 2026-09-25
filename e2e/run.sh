#!/usr/bin/env bash
#
# Tests de bout en bout contre un vrai démon Docker.
#
# La suite unitaire monte le handler au-dessus d'un faux démon : elle ne peut
# pas prouver que la découverte par label, la réécriture nom → ID, le filtrage
# du flux d'événements ou le frontend socket unix se comportent correctement
# face à dockerd. C'est ce que fait ce script.
#
#   ./e2e/run.sh            construit l'image puis déroule la suite
#   IMAGE=... ./e2e/run.sh  réutilise une image déjà construite

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

RUN_ID="e2e-$(date -u +%Y%m%d%H%M%S)-$$"
IMAGE="${IMAGE:-docker-socket-proxy:${RUN_ID}}"
NETWORK="${RUN_ID}-net"
VOLUME="${RUN_ID}-run"
PROXY="${RUN_ID}-proxy"
CLIENT_IMAGE="${CLIENT_IMAGE:-docker.io/curlimages/curl:latest}"

# Cibles manipulées par les tests de portée.
TARGET_ALLOWED="${RUN_ID}-target-allowed"
TARGET_HIDDEN="${RUN_ID}-target-hidden"

FAILURES=0
TESTS=0
CLIENTS=()
UNIX_CLIENT=""

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

pass() { TESTS=$((TESTS + 1)); printf '   \033[32mOK\033[0m   %s\n' "$*"; }
fail() {
	TESTS=$((TESTS + 1))
	FAILURES=$((FAILURES + 1))
	printf '   \033[31mÉCHEC\033[0m %s\n' "$*"
}

cleanup() {
	local code=$?
	log "Nettoyage"
	if [ "${KEEP:-0}" != "1" ] && [ -n "${PROXY:-}" ]; then
		docker logs "${PROXY}" >"${SCRIPT_DIR}/proxy.log" 2>&1 || true
		info "journal du proxy : ${SCRIPT_DIR}/proxy.log"
	fi
	docker rm -f "${PROXY}" "${TARGET_ALLOWED}" "${TARGET_HIDDEN}" >/dev/null 2>&1 || true
	if [ "${#CLIENTS[@]}" -gt 0 ]; then
		docker rm -f "${CLIENTS[@]}" >/dev/null 2>&1 || true
	fi
	docker network rm "${NETWORK}" >/dev/null 2>&1 || true
	docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
	rm -rf "${WORK_DIR:-}" 2>/dev/null || true
	exit "${code}"
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------

# Les clients sont des conteneurs persistants : un conteneur jetable par requête
# courrait contre la découverte, qui a besoin de voir le conteneur démarré avant
# que sa requête n'arrive.
client_name() { printf '%s-client-%s' "${RUN_ID}" "${1:-nolabel}"; }

start_client() {
	local role="$1" name
	name="$(client_name "${role:-nolabel}")"
	local args=(-d --name "${name}" --network "${NETWORK}" --entrypoint sleep)
	if [ -n "${role}" ]; then
		args+=(--label "socketproxy.role=${role}")
	fi
	docker run "${args[@]}" "${CLIENT_IMAGE}" 900 >/dev/null
	CLIENTS+=("${name}")
}

# curl_tcp <rôle> <méthode> <chemin> : rend le code HTTP.
curl_tcp() {
	local role="$1" method="$2" path="$3"
	docker exec "$(client_name "${role:-nolabel}")" \
		curl -s -o /dev/null -w '%{http_code}' -X "${method}" \
		"http://${PROXY}:2375${path}" 2>/dev/null || echo "000"
}

# curl_tcp_body rend le corps plutôt que le code.
curl_tcp_body() {
	local role="$1" method="$2" path="$3"
	docker exec "$(client_name "${role:-nolabel}")" \
		curl -s -X "${method}" "http://${PROXY}:2375${path}" 2>/dev/null || true
}

# curl_unix : requête à travers la socket unix dédiée, depuis un conteneur qui
# ne partage que le volume et n'a aucun accès réseau.
curl_unix() {
	local method="$1" path="$2"
	docker exec "${UNIX_CLIENT}" \
		curl -s -o /dev/null -w '%{http_code}' \
		--unix-socket /run/socketproxy/probe.sock \
		-X "${method}" "http://localhost${path}" 2>/dev/null || echo "000"
}

expect_status() {
	local want="$1" got="$2" label="$3"
	if [ "${got}" = "${want}" ]; then
		pass "${label} → ${got}"
	else
		fail "${label} → ${got} (attendu ${want})"
	fi
}

wait_for_proxy() {
	local attempt
	for attempt in $(seq 1 40); do
		if docker exec "${PROXY}" /usr/local/bin/docker-socket-proxy healthcheck >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	echo "le proxy n'a pas démarré" >&2
	docker logs "${PROXY}" >&2 || true
	return 1
}

# Laisse à la découverte le temps de prendre en compte un changement. La
# découverte est déclenchée par les événements Docker, avec un debounce court.
settle() { sleep "${SETTLE:-2}"; }

# --------------------------------------------------------------------------
# Préparation
# --------------------------------------------------------------------------

log "Préparation"

if [ -z "${IMAGE_PREBUILT:-}" ]; then
	info "construction de ${IMAGE}"
	docker build -q -t "${IMAGE}" "${REPO_DIR}" >/dev/null
fi
info "image : ${IMAGE}"

info "image cliente : ${CLIENT_IMAGE}"
docker pull -q "${CLIENT_IMAGE}" >/dev/null

WORK_DIR="$(mktemp -d)"
cat >"${WORK_DIR}/profiles.yml" <<EOF
# Lecture seule, sans droit d'écriture ni inspection.
reader:
  ping: true
  version: true
  containers: true

# Peut inspecter et redémarrer, mais uniquement la cible autorisée.
operator:
  ping: true
  version: true
  containers: true
  allow_inspect: true
  allow_restart: true
  events: true
  container_scope: allowlist
  allowed_containers:
    - ${TARGET_ALLOWED}

# Voit tout sauf la cible masquée, pour éprouver le filtrage des réponses.
watcher:
  ping: true
  version: true
  containers: true
  events: true
  container_scope: blacklist
  blocked_containers:
    - ${TARGET_HIDDEN}

# Profil lié à la socket unix dédiée.
probe:
  ping: true
  version: true
EOF

docker network create "${NETWORK}" >/dev/null
docker volume create "${VOLUME}" >/dev/null

log "Démarrage du proxy"
# --user 0:0 : sur la plupart des hôtes la socket Docker appartient à root, et
# l'e2e ne doit pas dépendre du GID docker local. En production, le proxy tourne
# sous l'UID 65532 avec un GID autorisé à lire la socket.
# Le fichier de profils est injecté par docker cp plutôt que par un bind :
# tous les hôtes ne partagent pas le répertoire temporaire avec le démon, et un
# bind d'un chemin absent crée un répertoire vide au lieu d'échouer.
docker create --name "${PROXY}" \
	--user 0:0 \
	--network "${NETWORK}" \
	-v /var/run/docker.sock:/var/run/docker.sock:ro \
	-v "${VOLUME}:/run/socketproxy" \
	-e SOCKETPROXY_PROFILE_FILE=/profiles.yml \
	-e PROXY_LISTEN_UNIX="/run/socketproxy/probe.sock:probe" \
	-e PROXY_LISTEN_UNIX_MODE=0666 \
	-e EVENT_DEBOUNCE_DELAY=50ms \
	-e DISCOVER_INTERVAL=5s \
	"${IMAGE}" >/dev/null
docker cp "${WORK_DIR}/profiles.yml" "${PROXY}:/profiles.yml" >/dev/null
docker start "${PROXY}" >/dev/null

wait_for_proxy
info "proxy démarré"

log "Clients et cibles"
for role in reader operator watcher inconnu "" ; do
	start_client "${role}"
done

UNIX_CLIENT="${RUN_ID}-client-unix"
docker run -d --name "${UNIX_CLIENT}" --network none --user 0:0 \
	-v "${VOLUME}:/run/socketproxy" --entrypoint sleep \
	"${CLIENT_IMAGE}" 900 >/dev/null
CLIENTS+=("${UNIX_CLIENT}")

docker run -d --name "${TARGET_ALLOWED}" --network "${NETWORK}" --entrypoint sleep "${CLIENT_IMAGE}" 600 >/dev/null
docker run -d --name "${TARGET_HIDDEN}" --network "${NETWORK}" --entrypoint sleep "${CLIENT_IMAGE}" 600 >/dev/null
settle
info "clients et cibles démarrés"

# --------------------------------------------------------------------------
# Frontend TCP : identification par label et par IP
# --------------------------------------------------------------------------

log "Frontend TCP — identification du client"

expect_status 200 "$(curl_tcp reader GET /version)" "reader autorisé sur /version"
expect_status 403 "$(curl_tcp '' GET /version)" "conteneur sans label refusé"
expect_status 403 "$(curl_tcp inconnu GET /version)" "rôle sans profil refusé"

log "Frontend TCP — droits par famille et par route"

expect_status 200 "$(curl_tcp reader GET /containers/json)" "reader liste les conteneurs"
expect_status 403 "$(curl_tcp reader GET "/containers/${TARGET_ALLOWED}/json")" "reader refusé sur inspect (allow_inspect absent)"
expect_status 403 "$(curl_tcp reader POST "/containers/${TARGET_ALLOWED}/restart")" "reader refusé sur restart"
expect_status 403 "$(curl_tcp reader GET /secrets)" "famille non accordée refusée"
expect_status 403 "$(curl_tcp reader GET /containers/../secrets)" "traversée de chemin refusée"

# --------------------------------------------------------------------------
# Portée conteneur, résolution nom → ID comprise
# --------------------------------------------------------------------------

log "Portée conteneur"

expect_status 204 "$(curl_tcp operator POST "/containers/${TARGET_ALLOWED}/restart")" "operator redémarre sa cible autorisée"
expect_status 403 "$(curl_tcp operator POST "/containers/${TARGET_HIDDEN}/restart")" "operator refusé hors de sa portée"

ALLOWED_ID="$(docker inspect --format '{{.Id}}' "${TARGET_ALLOWED}")"
expect_status 200 "$(curl_tcp operator GET "/containers/${ALLOWED_ID}/json")" "cible autorisée joignable par son ID complet"
expect_status 200 "$(curl_tcp operator GET "/containers/${ALLOWED_ID:0:12}/json")" "cible autorisée joignable par son ID court"

HIDDEN_ID="$(docker inspect --format '{{.Id}}' "${TARGET_HIDDEN}")"
expect_status 403 "$(curl_tcp operator GET "/containers/${HIDDEN_ID}/json")" "cible hors portée refusée même par son ID"

expect_status 403 "$(curl_tcp operator POST '/containers/create?name=escapade')" "création globale refusée pour un profil scopé"
expect_status 403 "$(curl_tcp operator POST /containers/prune)" "prune global refusé pour un profil scopé"

# --------------------------------------------------------------------------
# Filtrage des réponses : ce que le modèle par règles de chemin ne peut pas faire
# --------------------------------------------------------------------------

log "Filtrage de la liste des conteneurs"

LIST="$(curl_tcp_body watcher GET '/containers/json?all=1')"
if printf '%s' "${LIST}" | grep -q "${TARGET_ALLOWED}"; then
	pass "la cible autorisée apparaît dans la liste de watcher"
else
	fail "la cible autorisée est absente de la liste de watcher"
fi
if printf '%s' "${LIST}" | grep -q "${TARGET_HIDDEN}"; then
	fail "la cible masquée fuit dans la liste de watcher"
else
	pass "la cible masquée est absente de la liste de watcher"
fi

# La liste non filtrée doit, elle, contenir les deux : sinon le test ci-dessus
# passerait pour une raison sans rapport avec le filtrage.
RAW_LIST="$(curl_tcp_body reader GET '/containers/json?all=1')"
if printf '%s' "${RAW_LIST}" | grep -q "${TARGET_HIDDEN}"; then
	pass "un profil sans portée voit bien la cible masquée"
else
	fail "la cible masquée est invisible même sans portée : le test de filtrage ne prouve rien"
fi

# --------------------------------------------------------------------------
# Flux d'événements : un conteneur créé après coup doit être transmis
# --------------------------------------------------------------------------

log "Filtrage du flux d'événements"

EVENTS_FILE="${WORK_DIR}/events.txt"
EVENT_TARGET="${RUN_ID}-event-target"
docker exec "$(client_name watcher)" \
	curl -s --no-buffer --max-time 12 "http://${PROXY}:2375/events" >"${EVENTS_FILE}" 2>/dev/null &
EVENTS_PID=$!
sleep 3

# Créé après l'ouverture du flux : son événement arrive avant que la découverte
# ne l'ait indexé, ce qui est précisément le cas que le filtre doit traiter.
docker run -d --name "${EVENT_TARGET}" --network "${NETWORK}" "${CLIENT_IMAGE}" sleep 30 >/dev/null
sleep 2
docker rm -f "${TARGET_HIDDEN}" >/dev/null 2>&1 || true
sleep 2
docker rm -f "${EVENT_TARGET}" >/dev/null 2>&1 || true

wait "${EVENTS_PID}" 2>/dev/null || true

if grep -q "${EVENT_TARGET}" "${EVENTS_FILE}" 2>/dev/null; then
	pass "l'événement d'un conteneur créé après l'ouverture du flux est transmis"
else
	fail "l'événement d'un conteneur neuf est perdu (cache non encore peuplé)"
fi
if grep -q "${TARGET_HIDDEN}" "${EVENTS_FILE}" 2>/dev/null; then
	fail "les événements de la cible masquée fuient dans le flux"
else
	pass "les événements de la cible masquée sont filtrés"
fi

# --------------------------------------------------------------------------
# Frontend socket unix
# --------------------------------------------------------------------------

log "Frontend socket unix"

expect_status 200 "$(curl_unix GET /version)" "socket dédiée : /version autorisé par son profil"
expect_status 200 "$(curl_unix GET /_ping)" "socket dédiée : /_ping autorisé par son profil"
expect_status 403 "$(curl_unix GET /containers/json)" "socket dédiée : famille non accordée refusée"
expect_status 403 "$(curl_unix GET /info)" "socket dédiée : /info refusé"

SOCK_MODE="$(docker exec "${UNIX_CLIENT}" stat -c '%a' /run/socketproxy/probe.sock 2>/dev/null || echo '?')"
if [ "${SOCK_MODE}" = "666" ]; then
	pass "la socket porte le mode demandé (0666)"
else
	fail "mode de la socket = ${SOCK_MODE} (attendu 666)"
fi

# --------------------------------------------------------------------------
# Bilan
# --------------------------------------------------------------------------

log "Bilan"
printf '   %d test(s), %d échec(s)\n' "${TESTS}" "${FAILURES}"
[ "${FAILURES}" -eq 0 ]
