#!/bin/sh
set -e

SOCKET_PROXY_VERSION="${SOCKET_PROXY_VERSION:-main}"
SOCKET_PROXY_REVISION="${SOCKET_PROXY_REVISION:-dev}"

echo "==========================================="
echo "  docker-socket-proxy"
echo "    version : ${SOCKET_PROXY_VERSION}"
echo "    revision: ${SOCKET_PROXY_REVISION}"
echo "    uid/gid : $(id -u):$(id -g)"
echo "==========================================="

CFG_DIR="/tmp/haproxy"
CFG_FILE="${CFG_DIR}/haproxy.cfg"
RULES_FILE="${CFG_DIR}/rules.list"

mkdir -p "${CFG_DIR}"

# -------------------------------------------------------------------
# 1) Parse des arguments : --alias.key=value
#    Ex: --dockerproxy-homepage.containers=1
# -------------------------------------------------------------------
RULES=""
SERVICES=""

while [ "$#" -gt 0 ]; do
    arg="$1"
    shift

    case "${arg}" in
        --*=*)
            opt="${arg#--}"         # dockerproxy-homepage.containers=1
            svc="${opt%%.*}"        # dockerproxy-homepage
            rest="${opt#*.}"        # containers=1
            key="${rest%%=*}"       # containers
            val="${rest#*=}"        # 1

            # normalisation en minuscule
            key=$(echo "${key}" | tr 'A-Z' 'a-z')

            # normalisation des variantes éventuelles
            case "${key}" in
                allow_restarts|allow_restart|allowrestarts)
                    key="allow_restarts"
                    ;;
            esac

            SERVICES="${SERVICES} ${svc}"
            RULES="${RULES}
${svc}.${key}=${val}"
            ;;
        *)
            echo "WARN: argument ignoré (format non supporté) : ${arg}" >&2
            ;;
    esac
done

# Sauvegarde brute des règles (simple à re-parcourir)
printf '%s\n' "${RULES}" > "${RULES_FILE}"

# Déduplication simple des alias
UNIQUE_SERVICES=""
for svc in ${SERVICES}; do
    case " ${UNIQUE_SERVICES} " in
        *" ${svc} "*)
            ;;
        *)
            UNIQUE_SERVICES="${UNIQUE_SERVICES} ${svc}"
            ;;
    esac
done

# -------------------------------------------------------------------
# 2) Génération de la config HAProxy
# -------------------------------------------------------------------
{
    cat <<'EOF'
global
  log stdout format raw daemon
  master-worker

defaults
  log global
  mode http
  option httplog
  timeout connect 5s
  timeout client  60s
  timeout server  60s

backend docker-sock
  server docker /var/run/docker.sock

frontend docker-socket-proxy
  bind *:2375
  mode http
EOF
} > "${CFG_FILE}"

# 2.1) ACL host par service + deny global sur les hosts inconnus
HOST_ACLS=""

for svc in ${UNIQUE_SERVICES}; do
    [ -z "${svc}" ] && continue
    aclname="svc_${svc}_"
    echo "  acl ${aclname} hdr_reg(host) -i ^${svc}(:[0-9]+)?\$" >> "${CFG_FILE}"
    HOST_ACLS="${HOST_ACLS} ${aclname}"
done

if [ -n "${HOST_ACLS}" ]; then
    # On n'accepte que les hosts déclarés
    printf "  http-request deny unless" >> "${CFG_FILE}"
    for h in ${HOST_ACLS}; do
        printf " %s" "${h}" >> "${CFG_FILE}"
    done
    printf "\n" >> "${CFG_FILE}"
fi

# 2.2) Pour chaque service, on construit une allow-list par familles d’API
for svc in ${UNIQUE_SERVICES}; do
    [ -z "${svc}" ] && continue

    # flags pour ce service
    has_ping=0
    has_version=0
    has_info=0
    has_events=0
    has_auth=0
    has_build=0
    has_commit=0
    has_distribution=0
    has_exec=0
    has_system=0
    has_session=0

    has_containers=0
    has_images=0
    has_networks=0
    has_volumes=0
    has_services_flag=0
    has_tasks=0
    has_nodes=0
    has_swarm=0
    has_plugins=0
    has_secrets=0
    has_configs=0

    # on lit toutes les règles et on garde celles de ce service
    while IFS='= ' read -r lhs rhs; do
        [ -z "${lhs}" ] && continue

        case "${lhs}" in
            "${svc}."*)
                key="${lhs#${svc}.}"
                val="${rhs}"

                [ "${val}" != "1" ] && continue

                case "${key}" in
                    ping)          has_ping=1 ;;
                    version)       has_version=1 ;;
                    info)          has_info=1 ;;
                    events)        has_events=1 ;;
                    auth)          has_auth=1 ;;
                    build)         has_build=1 ;;
                    commit)        has_commit=1 ;;
                    distribution)  has_distribution=1 ;;
                    exec)          has_exec=1 ;;
                    system)        has_system=1 ;;
                    session)       has_session=1 ;;

                    containers)    has_containers=1 ;;
                    images)        has_images=1 ;;
                    networks)      has_networks=1 ;;
                    volumes)       has_volumes=1 ;;
                    services)      has_services_flag=1 ;;
                    tasks)         has_tasks=1 ;;
                    nodes)         has_nodes=1 ;;
                    swarm)         has_swarm=1 ;;
                    plugins)       has_plugins=1 ;;
                    secrets)       has_secrets=1 ;;
                    configs)       has_configs=1 ;;

                    # POST/DELETE/ALLOW_* sont acceptés mais, pour l’instant,
                    # on ne les utilise pas dans la génération des règles.
                    post)              ;;
                    delete)            ;;
                    allow_start)       ;;
                    allow_stop)        ;;
                    allow_restarts)    ;;
                    log_level)         ;;
                    *)
                        echo "WARN: clé '${key}' non gérée pour service '${svc}'" >&2
                        ;;
                esac
                ;;
        esac
    done < "${RULES_FILE}"

    ALLOW_ACLS=""

    # Fonctions utilitaires
    add_acl() {
        acl_name="$1"
        acl_rule="$2"
        echo "  acl ${acl_name} ${acl_rule}" >> "${CFG_FILE}"
        ALLOW_ACLS="${ALLOW_ACLS} ${acl_name}"
    }

    # --- Endpoints globaux (ping/version/info/events/auth/...) ---
    [ "${has_ping}" -eq 1 ]         && add_acl "${svc}__ping"         'path_reg ^/(v[0-9.]+/)?_ping$'
    [ "${has_version}" -eq 1 ]      && add_acl "${svc}__version"      'path_reg ^/(v[0-9.]+/)?version$'
    [ "${has_info}" -eq 1 ]         && add_acl "${svc}__info"         'path_reg ^/(v[0-9.]+/)?info$'
    [ "${has_events}" -eq 1 ]       && add_acl "${svc}__events"       'path_reg ^/(v[0-9.]+/)?events(/.*)?$'
    [ "${has_auth}" -eq 1 ]         && add_acl "${svc}__auth"         'path_reg ^/(v[0-9.]+/)?auth(/.*)?$'
    [ "${has_build}" -eq 1 ]        && add_acl "${svc}__build"        'path_reg ^/(v[0-9.]+/)?build(/.*)?$'
    [ "${has_commit}" -eq 1 ]       && add_acl "${svc}__commit"       'path_reg ^/(v[0-9.]+/)?commit(/.*)?$'
    [ "${has_distribution}" -eq 1 ] && add_acl "${svc}__distribution" 'path_reg ^/(v[0-9.]+/)?distribution(/.*)?$'
    [ "${has_exec}" -eq 1 ]         && add_acl "${svc}__exec"         'path_reg ^/(v[0-9.]+/)?containers/[^/]+/exec(/.*)?$'
    [ "${has_system}" -eq 1 ]       && add_acl "${svc}__system"       'path_reg ^/(v[0-9.]+/)?system(/.*)?$'
    [ "${has_session}" -eq 1 ]      && add_acl "${svc}__session"      'path_reg ^/(v[0-9.]+/)?session(/.*)?$'

    # --- Familles de ressources (containers/images/networks/...) ---
    [ "${has_containers}" -eq 1 ]   && add_acl "${svc}__containers"   'path_reg ^/(v[0-9.]+/)?containers(/.*)?$'
    [ "${has_images}" -eq 1 ]       && add_acl "${svc}__images"       'path_reg ^/(v[0-9.]+/)?images(/.*)?$'
    [ "${has_networks}" -eq 1 ]     && add_acl "${svc}__networks"     'path_reg ^/(v[0-9.]+/)?networks(/.*)?$'
    [ "${has_volumes}" -eq 1 ]      && add_acl "${svc}__volumes"      'path_reg ^/(v[0-9.]+/)?volumes(/.*)?$'
    [ "${has_services_flag}" -eq 1 ]&& add_acl "${svc}__services"     'path_reg ^/(v[0-9.]+/)?services(/.*)?$'
    [ "${has_tasks}" -eq 1 ]        && add_acl "${svc}__tasks"        'path_reg ^/(v[0-9.]+/)?tasks(/.*)?$'
    [ "${has_nodes}" -eq 1 ]        && add_acl "${svc}__nodes"        'path_reg ^/(v[0-9.]+/)?nodes(/.*)?$'
    [ "${has_swarm}" -eq 1 ]        && add_acl "${svc}__swarm"        'path_reg ^/(v[0-9.]+/)?swarm(/.*)?$'
    [ "${has_plugins}" -eq 1 ]      && add_acl "${svc}__plugins"      'path_reg ^/(v[0-9.]+/)?plugins(/.*)?$'
    [ "${has_secrets}" -eq 1 ]      && add_acl "${svc}__secrets"      'path_reg ^/(v[0-9.]+/)?secrets(/.*)?$'
    [ "${has_configs}" -eq 1 ]      && add_acl "${svc}__configs"      'path_reg ^/(v[0-9.]+/)?configs(/.*)?$'

    if [ -n "${ALLOW_ACLS}" ]; then
        # deny par défaut : on n’autorise que les ACL de la liste
        printf "  http-request deny if svc_%s_" "${svc}" >> "${CFG_FILE}"
        for a in ${ALLOW_ACLS}; do
            printf " !%s" "${a}" >> "${CFG_FILE}"
        done
        printf "\n" >> "${CFG_FILE}"
    else
        # aucun droit pour ce service => tout est refusé
        echo "  http-request deny if svc_${svc}_" >> "${CFG_FILE}"
    fi
done

echo "  default_backend docker-sock" >> "${CFG_FILE}"

echo "=== haproxy configuration generated ==="
cat "${CFG_FILE}"

# -------------------------------------------------------------------
# 3) Lancement de HAProxy
# -------------------------------------------------------------------
exec haproxy -f "${CFG_FILE}" -W -db
