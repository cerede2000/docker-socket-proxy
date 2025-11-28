#!/bin/sh
set -eu

# -----------------------------
#  Meta / logs
# -----------------------------
APP_VERSION="${APP_VERSION:-dev}"
APP_REVISION="${APP_REVISION:-dev}"

echo "==========================================="
echo " docker-socket-proxy"
echo "   version : ${APP_VERSION}"
echo "   revision: ${APP_REVISION}"
echo "   uid/gid : $(id -u):$(id -g)"
echo "==========================================="

# -----------------------------
#  Paramètres de base
# -----------------------------
# IMPORTANT : par défaut on met la conf dans /tmp
# pour être compatible avec read_only + tmpfs:/tmp
HAPROXY_CONFIG_DIR="${HAPROXY_CONFIG_DIR:-/tmp/haproxy}"
HAPROXY_CONFIG_FILE="${HAPROXY_CONFIG_DIR}/haproxy.cfg"

DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"
LISTEN_PORT="${LISTEN_PORT:-2375}"

mkdir -p "${HAPROXY_CONFIG_DIR}"

# -----------------------------
#  Parsing des arguments
#  Attendu : --service.feature=1
#  exemple : --dockerproxy-homepage.ping=1
# -----------------------------
SERVICES=""
RULES=""

for arg in "$@"; do
  case "$arg" in
    --*=*)
      opt="${arg#--}"          # dockerproxy-homepage.ping=1
      key="${opt%%=*}"         # dockerproxy-homepage.ping
      val="${opt#*=}"          # 1

      # ignore les flags à 0 ou vides
      [ -z "$val" ] && continue
      [ "$val" = "0" ] && continue

      case "$key" in
        *.*)
          svc="${key%%.*}"     # dockerproxy-homepage
          feat="${key#*.}"     # ping
          ;;
        *)
          echo "WARN: argument ignoré (format invalide, attendu --service.feature=1) : $arg" >&2
          continue
          ;;
      esac

      # Ajoute le service à la liste s'il n'y est pas encore
      case " $SERVICES " in
        *" $svc "*) ;;
        *) SERVICES="$SERVICES $svc" ;;
      esac

      # Mémorise la règle "svc.feature"
      RULES="$RULES $svc.$feat"
      ;;
    *)
      echo "WARN: argument ignoré (inconnu) : $arg" >&2
      ;;
  esac
done

# Nettoyage des espaces en tête
SERVICES=$(echo "$SERVICES" | sed 's/^ *//')
RULES=$(echo "$RULES" | sed 's/^ *//')

# -----------------------------
#  Génération du header HAProxy
# -----------------------------
{
  echo "global"
  echo "  log stdout format raw daemon"
  echo "  master-worker"
  echo ""
  echo "defaults"
  echo "  log global"
  echo "  mode http"
  echo "  option httplog"
  echo "  timeout connect 5s"
  echo "  timeout client  60s"
  echo "  timeout server  60s"
  echo ""
  echo "backend docker-sock"
  echo "  server docker ${DOCKER_SOCKET}"
  echo ""
  echo "frontend docker-socket-proxy"
  echo "  bind *:${LISTEN_PORT}"
  echo "  mode http"
} > "${HAPROXY_CONFIG_FILE}"

# -----------------------------
#  ACL Host par service
#  + règle globale "deny unless <un des hosts>"
# -----------------------------
HOST_DENY_COND=""

for svc in $SERVICES; do
  # Nom safe pour les ACL haproxy (remplace tout sauf [A-Za-z0-9_] par _)
  svc_id=$(echo "$svc" | tr -c 'A-Za-z0-9_' '_')
  svc_acl="svc_${svc_id}"

  # Host = <alias réseau> OU <alias réseau>:port
  echo "  acl ${svc_acl} hdr_reg(host) -i ^${svc}(:[0-9]+)?\$" >> "${HAPROXY_CONFIG_FILE}"

  if [ -z "$HOST_DENY_COND" ]; then
    HOST_DENY_COND="${svc_acl}"
  else
    HOST_DENY_COND="${HOST_DENY_COND} or ${svc_acl}"
  fi
done

if [ -n "$HOST_DENY_COND" ]; then
  echo "  http-request deny unless ${HOST_DENY_COND}" >> "${HAPROXY_CONFIG_FILE}"
else
  echo "  # Aucun service configuré -> tout refusé" >> "${HAPROXY_CONFIG_FILE}"
  echo "  http-request deny" >> "${HAPROXY_CONFIG_FILE}"
fi

# -----------------------------
#  ACL Path par service
#  + deny si host match mais path non autorisé
# -----------------------------
for svc in $SERVICES; do
  svc_id=$(echo "$svc" | tr -c 'A-Za-z0-9_' '_')
  svc_acl="svc_${svc_id}"
  ALLOWED_ACLS=""

  for rule in $RULES; do
    case "$rule" in
      "$svc".*)
        feat="${rule#*.}"     # ping / version / info / containers / events / images ...
        acl_name="${svc_id}_${feat}"

        case "$feat" in
          ping)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?_ping\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          version)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?version\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          info)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?info\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          containers)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?containers(/.*)?\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          events)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?events(/.*)?\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          images)
            echo "  acl ${acl_name} path_reg ^/(v[0-9.]+/)?images(/.*)?\$" >> "${HAPROXY_CONFIG_FILE}"
            ;;
          *)
            echo "WARN: feature non supportée '${feat}' pour le service '${svc}'" >&2
            continue
            ;;
        esac

        case " $ALLOWED_ACLS " in
          *" ${acl_name} "*) ;;
          *) ALLOWED_ACLS="${ALLOWED_ACLS} ${acl_name}" ;;
        esac
        ;;
    esac
  done

  ALLOWED_ACLS=$(echo "$ALLOWED_ACLS" | sed 's/^ *//')

  if [ -n "$ALLOWED_ACLS" ]; then
    # Exemple :
    # http-request deny if svc_dockerproxy_homepage !dockerproxy_homepage_ping !dockerproxy_homepage_version ...
    echo "  http-request deny if ${svc_acl} !${ALLOWED_ACLS}" >> "${HAPROXY_CONFIG_FILE}"
  else
    echo "  # Aucun path autorisé pour le host ${svc} -> tout refusé pour ce host" >> "${HAPROXY_CONFIG_FILE}"
    echo "  http-request deny if ${svc_acl}" >> "${HAPROXY_CONFIG_FILE}"
  fi
done

echo "  default_backend docker-sock" >> "${HAPROXY_CONFIG_FILE}"

echo
echo "===== Génération de la configuration HAProxy ====="
sed 's/^/  > /' "${HAPROXY_CONFIG_FILE}"
echo "=================================================="
echo

# -----------------------------
#  Lancement d'HAProxy
# -----------------------------
exec haproxy -f "${HAPROXY_CONFIG_FILE}" -W -db
