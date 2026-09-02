#!/usr/bin/env bash
# Network isolation for offline CyberGym runs (iptables on the WSL host).
#
# Blocks outbound public traffic; permits only the internal model API, the local
# CyberGym server (loopback) and already-established connections.
#
# The internal model API endpoint is intranet info and is NOT hardcoded here.
# It is resolved in this order:
#   1. env API_HOST / API_PORT   e.g.  sudo API_HOST=1.2.3.4 API_PORT=9000 bash netlock.sh
#   2. [agent] base_url in config.toml.local under the project root
#      (config.toml.local is gitignored and holds the real internal address)
#
# Usage:
#   sudo bash netlock.sh                      # run from the project root
#   sudo bash netlock.sh --root /path/to/proj # explicit project root
#
# Effect: docker pull / opencode plugin updates / github etc. become unavailable.
# Lift it with:  sudo bash netunlock.sh
set -e

# Resolve project root (default: this script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--root" ]]; then
  PROJECT_ROOT="${2:?--root needs a path}"
  shift 2
else
  PROJECT_ROOT="$SCRIPT_DIR"
fi

# Resolve the internal model API endpoint (intranet value stays local-only).
API_HOST="${API_HOST:-}"
API_PORT="${API_PORT:-}"
if [[ -z "$API_HOST" || -z "$API_PORT" ]]; then
  local_cfg="$PROJECT_ROOT/config.toml.local"
  if [[ -f "$local_cfg" ]]; then
    base_url="$(sed -nE 's/^[[:space:]]*base_url[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$local_cfg" | head -1)"
    if [[ -n "$base_url" ]]; then
      base_url="${base_url#*://}"
      [[ -z "$API_HOST" ]] && API_HOST="${base_url%%:*}"
      if [[ "$base_url" == *:* ]]; then
        [[ -z "$API_PORT" ]] && API_PORT="${base_url##*:}"
      fi
    fi
  fi
fi
if [[ -z "$API_HOST" || -z "$API_PORT" ]]; then
  echo "ERROR: cannot resolve the internal API endpoint. Set API_HOST/API_PORT, or ensure" >&2
  echo "config.toml.local contains [agent] base_url = \"http://host:port\" under $PROJECT_ROOT" >&2
  exit 2
fi

echo "== 1. allow internal API (${API_HOST}:${API_PORT}) and loopback =="
iptables -I OUTPUT 1 -d "$API_HOST" -p tcp --dport "$API_PORT" -j ACCEPT
iptables -I OUTPUT 2 -d 127.0.0.1 -j ACCEPT
iptables -I OUTPUT 3 -d 0.0.0.0/8 -j ACCEPT

echo "== 2. allow established connection replies =="
iptables -I OUTPUT 4 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "== 3. drop public outbound by default (keep the model offline) =="
iptables -A OUTPUT -j DROP

echo "== 4. verify rules =="
iptables -L OUTPUT -n --line-numbers

echo "== 5. probe internal API still reachable =="
curl -s -o /dev/null -w "api_http=%{http_code}\n" -m 5 "http://${API_HOST}:${API_PORT}/" \
  || echo "api probe returned non-2xx (expected for bare path)"

echo "== 6. probe public internet blocked =="
timeout 5 curl -sI https://github.com 2>&1 | head -1 || echo "OUTBOUND_BLOCKED (expected)"
echo "DONE. To lift the restriction: sudo bash netunlock.sh"
