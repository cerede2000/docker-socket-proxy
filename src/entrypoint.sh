#!/bin/sh
set -eu

CONFIG_FILE="/tmp/haproxy.cfg"
SERVICES_FILE="/tmp/services_perms"

: > "$SERVICES_FILE"

DOCKER_SOCKET_PATH="${DOCKER_SOCKET_PATH:-/var/run/docker.sock}"
LISTEN_PORT="${SOCKET_PROXY_PORT:-2375}"

# --------------------------------
# Affichage version / SHA au démarrage
# --------------------------------
echo "docker-socket-proxy version: ${APP_VERSION:-unknown} (sha ${APP_GIT_SHA:-unknown})"
echo "Using Docker socket: ${DOCKER_SOCKET_PATH}, listening on port ${LISTEN_PORT}"
echo

# -----------------------------
# Parsing des arguments
#   --dockerproxy-traefik.ping=1
#   --dockerproxy-watchtower.containers=1
# -----------------------------
for arg in "$@"; do
  case "$arg" in
    --*)
      arg="${arg#--}"           # supprime les "--"
      key="${arg%%=*}"          # avant le "="
      val="${arg#*=}"           # après le "="
      [ "$key" = "$val" ] && val="1"   # si pas de "=", on assume 1

      svc="${key%%.*}"
      perm="${key#*.}"

      [ -z "$svc" ] && continue
      [ -z "$perm" ] && continue

      case "$val" in
        0|false|False|no|No) continue ;;  # désactivé
      esac

      echo "$svc $perm" >> "$SERVICES_FILE"
      ;;
  esac
done

services="$(awk '{print $1}' "$SERVICES_FILE" 2>/dev/null | sort -u || true)"

# -----------------------------
# Header HAProxy
# -----------------------------
cat > "$CONFIG_FILE" <<EOF
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
  server docker ${DOCKER_SOCKET_PATH}
EOF

echo >> "$CONFIG_FILE"
echo "frontend docker-socket-proxy" >> "$CONFIG_FILE"
echo "  bind *:${LISTEN_PORT}" >> "$CONFIG_FILE"
echo "  mode http" >> "$CONFIG_FILE"

if [ -z "$services" ]; then
  echo "  # Aucun service configuré -> on bloque tout" >> "$CONFIG_FILE"
  echo "  http-request deny" >> "$CONFIG_FILE"
else
  # -----------------------------
  # ACL des hosts connus (alias réseau)
  # -----------------------------
  known_hosts_acl=""
  for svc in $services; do
    echo "  acl svc_${svc} hdr(host) -i ${svc}" >> "$CONFIG_FILE"
    if [ -z "$known_hosts_acl" ]; then
      known_hosts_acl="svc_${svc}"
    else
      known_hosts_acl="${known_hosts_acl} or svc_${svc}"
    fi
  done

  # Tout host inconnu est refusé
  echo "  http-request deny unless ${known_hosts_acl}" >> "$CONFIG_FILE"

  # -----------------------------
  # Permissions par service
  # -----------------------------
  for svc in $services; do
    perms="$(awk -v s="$svc" '$1==s {print $2}' "$SERVICES_FILE" | tr '\n' ' ')"

    ALLOWED_ACLS=""

    for perm in $perms; do
      case "$perm" in
        ping)
          echo "  acl ${svc}_ping path_reg ^/(v[0-9.]+/)?_ping\$" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_ping"
          ;;
        version)
          echo "  acl ${svc}_version path_reg ^/(v[0-9.]+/)?version\$" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_version"
          ;;
        info)
          echo "  acl ${svc}_info path_reg ^/(v[0-9.]+/)?info\$" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_info"
          ;;
        events)
          echo "  acl ${svc}_events path_reg ^/(v[0-9.]+/)?events(/.*)?\$" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_events"
          ;;
        containers|images|networks|volumes|system)
          echo "  acl ${svc}_${perm} path_reg ^/(v[0-9.]+/)?${perm}(/.*)?\$" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_${perm}"
          ;;
        post)
          echo "  acl ${svc}_post method POST" >> "$CONFIG_FILE"
          ALLOWED_ACLS="${ALLOWED_ACLS} ${svc}_post"
          ;;
        *)
          echo "  # permission inconnue ignorée: ${svc}.${perm}" >> "$CONFIG_FILE"
          ;;
      esac
    done

    if [ -n "$ALLOWED_ACLS" ]; then
      # si host = svc_X et qu'aucune ACL permise ne matche => deny
      deny_line="  http-request deny if svc_${svc}"
      for a in $ALLOWED_ACLS; do
        deny_line="${deny_line} !${a}"
      done
      echo "$deny_line" >> "$CONFIG_FILE"
    else
      # aucun droit déclaré pour ce host => tout refusé
      echo "  http-request deny if svc_${svc}" >> "$CONFIG_FILE"
    fi
  done
fi

echo "  default_backend docker-sock" >> "$CONFIG_FILE"

exec haproxy -f "$CONFIG_FILE" -db
