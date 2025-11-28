#!/bin/sh
set -eu

VERSION="${DOCKER_SOCKET_PROXY_VERSION:-main}"
REVISION="${DOCKER_SOCKET_PROXY_REVISION:-dev}"
SOCKET_PATH="${SOCKET_PATH:-/var/run/docker.sock}"
PROXY_PORT="${PROXY_PORT:-2375}"
# IMPORTANT : on écrit dans /tmp pour supporter read_only: true
HAPROXY_CFG="${HAPROXY_CFG:-/tmp/haproxy.cfg}"

echo " ==========================================="
echo "  docker-socket-proxy"
echo "    version : ${VERSION}"
echo "    revision: ${REVISION}"
echo "    uid/gid : $(id -u):$(id -g)"
echo " ==========================================="

# Normalise le nom de service pour servir de clé de variable
svc_key() {
  # ex: proxy-homepage -> PROXY_HOMEPAGE
  echo "$1" | tr '[:lower:]' '[:upper:]' | tr '.-' '__'
}

SERVICES=""

# Parse les arguments du type:
#   --proxy-homepage.containers=1
#   --proxy-watchtower.post=1
for arg in "$@"; do
  case "$arg" in
    --*)
      opt="${arg#--}"        # proxy-homepage.containers=1
      name="${opt%%=*}"      # proxy-homepage.containers
      val="${opt#*=}"        # 1 ou tout le bloc si pas de '='

      # Pas de "=", on considère que c'est =1
      if [ "$val" = "$name" ]; then
        val="1"
      fi

      service="${name%%.*}"  # proxy-homepage
      flag="${name#*.}"      # containers

      # Ignore si pas de point
      if [ "$service" = "$name" ] || [ -z "$flag" ]; then
        continue
      fi

      svc_var_key=$(svc_key "$service")
      flag_var_key=$(echo "$flag" | tr '[:lower:]' '[:upper:]' | tr '.-' '__')

      # Ajoute à la liste des services si nouveau
      case " $SERVICES " in
        *" $service "*) ;;
        *) SERVICES="$SERVICES $service" ;;
      esac

      eval "SERVICE_${svc_var_key}_${flag_var_key}=\"$val\""
      ;;
  esac
done

# Helper pour lire un flag booléen d'un service
get_flag() {
  service="$1"
  key="$2" # déjà UPPERCASE avec underscores
  svc_var_key=$(svc_key "$service")
  var="SERVICE_${svc_var_key}_${key}"
  eval "val=\${$var-}"
  case "$val" in
    1|true|TRUE|yes|YES|on|ON) echo 1 ;;
    *) echo 0 ;;
  esac
}

# Helper pour lire une valeur brute (string) d'un service
get_value() {
  service="$1"
  key="$2" # déjà UPPERCASE avec underscores
  svc_var_key=$(svc_key "$service")
  var="SERVICE_${svc_var_key}_${key}"
  eval "val=\${$var-}"
  echo "$val"
}

# Premier LOG_LEVEL trouvé (facultatif, surtout pour info)
LOG_LEVEL="info"
for s in $SERVICES; do
  svc_var_key=$(svc_key "$s")
  var="SERVICE_${svc_var_key}_LOG_LEVEL"
  eval "lvl=\${$var-}"
  if [ -n "$lvl" ]; then
    LOG_LEVEL="$lvl"
    break
  fi
done

echo "   log level: ${LOG_LEVEL}"
echo " ==========================================="

mkdir -p "$(dirname "$HAPROXY_CFG")"

# Header HAProxy
{
  echo "global"
  echo "  log stdout format raw daemon"
  echo "  master-worker"
  echo
  echo "defaults"
  echo "  log global"
  echo "  mode http"
  echo "  option httplog"
  echo "  timeout connect 5s"
  echo "  timeout client  60s"
  echo "  timeout server  60s"
  echo
  echo "backend docker-sock"
  echo "  server docker ${SOCKET_PATH}"
  echo
  echo "frontend docker-socket-proxy"
  echo "  bind [::]:${PROXY_PORT} v4v6"
  echo "  mode http"
  echo
  echo "  log-format \"%ci:%cp [%t] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq alias:%[var(txn.service)] execctx:%[sc0_gpc0] %HM %HU path-before:%[var(txn.path_before)] path-after:%[var(txn.path_after)]\""
  echo
  echo "  # Debug : mémoriser le path initial pour le log"
  echo "  http-request set-var(txn.path_before) path"
  echo "  http-request set-var(txn.path_after) path"
  echo
  echo "  # Méthodes HTTP"
  echo "  acl m_read  method GET HEAD OPTIONS"
  echo "  acl m_write method POST PUT PATCH DELETE"
  echo
  echo "  # ACL de chemins communes (Docker API, avec ou sans prefix /vX.Y/)"
  echo "  acl path_ping         path_reg ^/(v[0-9.]+/)?_ping\$"
  echo "  acl path_version      path_reg ^/(v[0-9.]+/)?version\$"
  echo "  acl path_info         path_reg ^/(v[0-9.]+/)?info\$"
  echo "  acl path_events       path_reg ^/(v[0-9.]+/)?events"
  echo "  acl path_auth         path_reg ^/(v[0-9.]+/)?auth(/.*)?\$"
  echo "  acl path_build        path_reg ^/(v[0-9.]+/)?build(/.*)?\$"
  echo "  acl path_commit       path_reg ^/(v[0-9.]+/)?commit(/.*)?\$"
  echo "  acl path_configs      path_reg ^/(v[0-9.]+/)?configs(/.*)?\$"
  echo "  acl path_containers   path_reg ^/(v[0-9.]+/)?containers(/.*)?\$"
  echo "  acl path_cont_start   path_reg ^/(v[0-9.]+/)?containers/[^/]+/start\$"
  echo "  acl path_cont_stop    path_reg ^/(v[0-9.]+/)?containers/[^/]+/stop\$"
  echo "  acl path_cont_restart path_reg ^/(v[0-9.]+/)?containers/[^/]+/restart\$"
  echo "  acl path_cont_exec    path_reg ^/(v[0-9.]+/)?containers/[^/]+/exec\$"
  echo "  acl path_distribution path_reg ^/(v[0-9.]+/)?distribution(/.*)?\$"
  echo "  acl path_exec         path_reg ^/(v[0-9.]+/)?exec(/.*)?\$"
  echo "  acl path_exec_root    path_reg ^/exec(/.*)?\$"
  echo "  acl path_images       path_reg ^/(v[0-9.]+/)?images(/.*)?\$"
  echo "  acl path_networks     path_reg ^/(v[0-9.]+/)?networks(/.*)?\$"
  echo "  acl path_nodes        path_reg ^/(v[0-9.]+/)?nodes(/.*)?\$"
  echo "  acl path_plugins      path_reg ^/(v[0-9.]+/)?plugins(/.*)?\$"
  echo "  acl path_secrets      path_reg ^/(v[0-9.]+/)?secrets(/.*)?\$"
  echo "  acl path_services     path_reg ^/(v[0-9.]+/)?services(/.*)?\$"
  echo "  acl path_session      path_reg ^/(v[0-9.]+/)?session(/.*)?\$"
  echo "  acl path_swarm        path_reg ^/(v[0-9.]+/)?swarm(/.*)?\$"
  echo "  acl path_system       path_reg ^/(v[0-9.]+/)?system(/.*)?\$"
  echo "  acl path_tasks        path_reg ^/(v[0-9.]+/)?tasks(/.*)?\$"
  echo "  acl path_volumes      path_reg ^/(v[0-9.]+/)?volumes(/.*)?\$"
  echo
  echo "  # Stick-table : contexte exec par IP (Portainer)"
  echo "  stick-table type ip size 1k expire 30s store gpc0"
  echo "  acl has_exec_ctx sc0_gpc0 gt 0"
  echo
  echo "  # ACL d'hôtes / aliases de services"
} > "$HAPROXY_CFG"

# ACL d’host par service + alias pour les logs + tracking exec pour proxy-portainer
ALLOWED_HOST_ACLS=""
for service in $SERVICES; do
  svc_var_key=$(svc_key "$service")
  svc_acl="svc_${svc_var_key}"

  echo "  acl ${svc_acl} hdr_reg(host) -i ^${service}(:[0-9]+)?$" >> "$HAPROXY_CFG"
  echo "  http-request set-var(txn.service) str(\"${service}\") if ${svc_acl}" >> "$HAPROXY_CFG"

  # ICI on ajoute pour proxy-portainer
  if [ "$service" = "proxy-portainer" ]; then
    # Quand Portainer fait POST /vX.Y/containers/<id>/exec, on marque l’IP dans la stick-table
    echo "  http-request sc-inc-gpc0(0) if ${svc_acl} path_cont_exec m_write" >> "$HAPROXY_CFG"
  fi

  ALLOWED_HOST_ACLS="$ALLOWED_HOST_ACLS ${svc_acl}"
done

# Autoriser :
#   - /version (pour healthcheck)
#   - /exec/... (root) UNIQUEMENT si has_exec_ctx (exec préparé via proxy-portainer)
#   - tout ce qui matche un alias de service
if [ -n "$ALLOWED_HOST_ACLS" ]; then
  cond="path_version || path_exec_root has_exec_ctx"
  for a in $ALLOWED_HOST_ACLS; do
    cond="$cond || $a"
  done
  echo "  http-request deny unless ${cond}" >> "$HAPROXY_CFG"
fi

# Règles par service
for service in $SERVICES; do
  svc_var_key=$(svc_key "$service")
  svc_acl="svc_${svc_var_key}"

  PING=$(get_flag "$service" "PING")
  VERSION=$(get_flag "$service" "VERSION")
  INFO=$(get_flag "$service" "INFO")

  EVENTS=$(get_flag "$service" "EVENTS")
  # alias "event" → "EVENTS" si besoin
  if [ "$EVENTS" -eq 0 ]; then
    EVENTS=$(get_flag "$service" "EVENT")
  fi

  AUTH=$(get_flag "$service" "AUTH")
  BUILD=$(get_flag "$service" "BUILD")
  COMMIT=$(get_flag "$service" "COMMIT")
  CONFIGS=$(get_flag "$service" "CONFIGS")
  CONTAINERS=$(get_flag "$service" "CONTAINERS")
  DISTRIBUTION=$(get_flag "$service" "DISTRIBUTION")
  EXEC=$(get_flag "$service" "EXEC")
  IMAGES=$(get_flag "$service" "IMAGES")
  NETWORKS=$(get_flag "$service" "NETWORKS")
  NODES=$(get_flag "$service" "NODES")
  PLUGINS=$(get_flag "$service" "PLUGINS")
  SECRETS=$(get_flag "$service" "SECRETS")
  SERVICES_FLAG=$(get_flag "$service" "SERVICES")
  SESSION=$(get_flag "$service" "SESSION")
  SWARM=$(get_flag "$service" "SWARM")
  SYSTEM=$(get_flag "$service" "SYSTEM")
  TASKS=$(get_flag "$service" "TASKS")
  VOLUMES=$(get_flag "$service" "VOLUMES")

  POST=$(get_flag "$service" "POST")
  ALLOW_START=$(get_flag "$service" "ALLOW_START")
  ALLOW_STOP=$(get_flag "$service" "ALLOW_STOP")

  ALLOW_RESTARTS=$(get_flag "$service" "ALLOW_RESTARTS")
  # alias "allow_restart" → "ALLOW_RESTARTS"
  if [ "$ALLOW_RESTARTS" -eq 0 ]; then
    ALLOW_RESTARTS=$(get_flag "$service" "ALLOW_RESTART")
  fi

  # lecture APIREWRITE brute (ex: 1.51)
  API_REWRITE=$(get_value "$service" "APIREWRITE")

  echo "" >> "$HAPROXY_CFG"
  echo "  # Règles pour le service ${service}" >> "$HAPROXY_CFG"

  # Si API_REWRITE défini -> rewrite global de la version d'API
  if [ -n "$API_REWRITE" ] && [ "$API_REWRITE" != "0" ]; then
    echo "  # API version rewrite for ${service} -> v${API_REWRITE} (ALL endpoints)" >> "$HAPROXY_CFG"
    echo "  http-request replace-path ^/v[0-9.]+(/.*)\$ /v${API_REWRITE}\1 if ${svc_acl}" >> "$HAPROXY_CFG"
    echo "  http-request replace-path ^/engine/api/v[0-9.]+(/.*)\$ /engine/api/v${API_REWRITE}\1 if ${svc_acl}" >> "$HAPROXY_CFG"
  fi

  # Liste des chemins autorisés pour ce service
  allowed=""
  [ "$PING" -eq 1 ]          && allowed="$allowed path_ping"
  [ "$VERSION" -eq 1 ]       && allowed="$allowed path_version"
  [ "$INFO" -eq 1 ]          && allowed="$allowed path_info"
  [ "$EVENTS" -eq 1 ]        && allowed="$allowed path_events"
  [ "$AUTH" -eq 1 ]          && allowed="$allowed path_auth"
  [ "$BUILD" -eq 1 ]         && allowed="$allowed path_build"
  [ "$COMMIT" -eq 1 ]        && allowed="$allowed path_commit"
  [ "$CONFIGS" -eq 1 ]       && allowed="$allowed path_configs"
  [ "$CONTAINERS" -eq 1 ]    && allowed="$allowed path_containers"
  [ "$DISTRIBUTION" -eq 1 ]  && allowed="$allowed path_distribution"
  [ "$EXEC" -eq 1 ]          && allowed="$allowed path_exec"
  [ "$IMAGES" -eq 1 ]        && allowed="$allowed path_images"
  [ "$NETWORKS" -eq 1 ]      && allowed="$allowed path_networks"
  [ "$NODES" -eq 1 ]         && allowed="$allowed path_nodes"
  [ "$PLUGINS" -eq 1 ]       && allowed="$allowed path_plugins"
  [ "$SECRETS" -eq 1 ]       && allowed="$allowed path_secrets"
  [ "$SERVICES_FLAG" -eq 1 ] && allowed="$allowed path_services"
  [ "$SESSION" -eq 1 ]       && allowed="$allowed path_session"
  [ "$SWARM" -eq 1 ]         && allowed="$allowed path_swarm"
  [ "$SYSTEM" -eq 1 ]        && allowed="$allowed path_system"
  [ "$TASKS" -eq 1 ]         && allowed="$allowed path_tasks"
  [ "$VOLUMES" -eq 1 ]       && allowed="$allowed path_volumes"

  if [ -n "$allowed" ]; then
    neg=""
    for p in $allowed; do
      neg="$neg !$p"
    done
    # si host = service mais path non dans la liste -> 403
    echo "  http-request deny if ${svc_acl}${neg}" >> "$HAPROXY_CFG"
  else
    # si aucun chemin autorisé pour ce service -> tout refuser
    echo "  http-request deny if ${svc_acl}" >> "$HAPROXY_CFG"
  fi

  # Gestion de POST / méthodes en écriture
  if [ "$POST" -eq 0 ]; then
    # POST=0 => aucune écriture possible
    echo "  http-request deny if ${svc_acl} m_write" >> "$HAPROXY_CFG"
  else
    # POST=1 => on autorise les écritures, mais on peut bloquer start/stop/restart
    if [ "$ALLOW_START" -eq 0 ]; then
      echo "  http-request deny if ${svc_acl} m_write path_cont_start" >> "$HAPROXY_CFG"
    fi
    if [ "$ALLOW_STOP" -eq 0 ]; then
      echo "  http-request deny if ${svc_acl} m_write path_cont_stop" >> "$HAPROXY_CFG"
    fi
    if [ "$ALLOW_RESTARTS" -eq 0 ]; then
      echo "  http-request deny if ${svc_acl} m_write path_cont_restart" >> "$HAPROXY_CFG"
    fi
  fi
done

echo "" >> "$HAPROXY_CFG"
# Debug : path final après éventuels rewrites
echo "  http-request set-var(txn.path_after) path" >> "$HAPROXY_CFG"
echo "  default_backend docker-sock" >> "$HAPROXY_CFG"

echo
echo "Generated HAProxy configuration:"
echo "--------------------------------"
cat "$HAPROXY_CFG"
echo "--------------------------------"

exec haproxy -W -db -f "$HAPROXY_CFG"
