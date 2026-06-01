#!/usr/bin/env bash
# fleet.sh runs demon across a fleet of machines YOU CONTROL, in lockstep.
#
# this is the legitimate answer to the single machine ceiling: instead of one
# process on one uplink, you rent N boxes (or use lab machines you own), and run
# demon on each against the same authorized target. it is NOT a botnet, there is
# no infection, no persistence, no callback C2. it uses plain SSH to machines you
# already have credentials for, pushes the binary, runs it, and on ctrl+c stops
# every remote process cleanly. you are responsible for the same authorization on
# every host AND on the target that a single-machine run requires.
#
# requirements:
#   - key-based SSH access to every host (BatchMode is on; password auth will fail
#     fast rather than hang the fleet)
#   - Go toolchain locally (to cross-compile the binary that ships to the hosts)
#
# usage:
#   ./fleet.sh <hosts_file> <target> [demon flags...]
#
#   hosts_file   one host per line as [user@]host[:ssh_port]; blank lines and
#                lines starting with # are ignored. see fleet_hosts.example
#   target       passed straight through to demon on every host
#   demon flags  any demon flags (e.g. -attack 2 -concurrency 300 -rate 5000
#                -duration 5m); applied identically on every host
#
# env overrides:
#   FLEET_GOOS   remote GOOS for the cross-compile (default: linux)
#   FLEET_GOARCH remote GOARCH (default: amd64)
#   SSH_OPTS     extra ssh/scp options (default: sensible timeouts + accept-new)
#
# examples:
#   ./fleet.sh hosts.txt https://example.com -attack 2 -concurrency 300 -rate 5000 -duration 5m
#   ./fleet.sh hosts.txt https://example.com -attack 0,3 -rate 8000 -rotate-ua -infinite

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <hosts_file> <target> [demon flags...]"
    echo "  example: $0 hosts.txt https://example.com -attack 2 -concurrency 300 -rate 5000 -duration 5m"
    exit 1
fi

HOSTS_FILE="$1"
TARGET="$2"
shift 2
DEMON_ARGS=("$@")
# pre-joined string form; $* is always defined under `set -u` even when empty,
# which keeps us safe on macOS's default bash 3.2 where "${arr[@]}" on an empty
# array trips "unbound variable".
DEMON_ARGS_STR="$*"

if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "hosts file not found: $HOSTS_FILE"
    exit 1
fi

GOOS_REMOTE="${FLEET_GOOS:-linux}"
GOARCH_REMOTE="${FLEET_GOARCH:-amd64}"
RUN_ID="fleet-$(date +%s)-$$"
REMOTE_BIN="/tmp/demon-${RUN_ID}"
LOCAL_BIN="$(dirname "$0")/demon-${RUN_ID}.bin"
# shellcheck disable=SC2206
SSH_OPTS_ARR=(${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o BatchMode=yes})

# read hosts, skipping blanks and comments
HOSTS=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"                 # strip inline comments
    line="$(echo "$line" | xargs)"     # trim whitespace
    [[ -z "$line" ]] && continue
    HOSTS+=("$line")
done < "$HOSTS_FILE"

if [[ ${#HOSTS[@]} -eq 0 ]]; then
    echo "no hosts found in $HOSTS_FILE"
    exit 1
fi

echo ""
echo "fleet:    ${#HOSTS[@]} hosts"
echo "target:   $TARGET"
echo "args:     ${DEMON_ARGS_STR:-<none>}"
echo "remote:   $GOOS_REMOTE/$GOARCH_REMOTE -> $REMOTE_BIN"
echo "run id:   $RUN_ID"
echo ""

# split a hosts file entry into ssh target + optional -p port
ssh_target() { echo "${1%%:*}"; }
ssh_port()   { [[ "$1" == *:* ]] && echo "${1##*:}" || echo ""; }

# cross-compile the binary that ships to the hosts
echo "[build] cross-compiling demon for $GOOS_REMOTE/$GOARCH_REMOTE..."
( cd "$(dirname "$0")" && GOOS="$GOOS_REMOTE" GOARCH="$GOARCH_REMOTE" CGO_ENABLED=0 go build -o "$(basename "$LOCAL_BIN")" . )
echo "[build] ok"

PIDS=()

cleanup() {
    echo ""
    echo "stopping fleet ($RUN_ID)..."
    # signal every remote demon to shut down gracefully (demon traps SIGINT)
    for h in "${HOSTS[@]}"; do
        local_target="$(ssh_target "$h")"
        local_port="$(ssh_port "$h")"
        port_opt=(); [[ -n "$local_port" ]] && port_opt=(-p "$local_port")
        ssh "${SSH_OPTS_ARR[@]}" "${port_opt[@]}" "$local_target" \
            "pkill -INT -f '$REMOTE_BIN' 2>/dev/null; sleep 1; rm -f '$REMOTE_BIN' 2>/dev/null" \
            </dev/null >/dev/null 2>&1 || true
    done
    # reap local ssh streamers (guard empty array for bash 3.2 under set -u)
    if [[ ${#PIDS[@]} -gt 0 ]]; then
        for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    fi
    rm -f "$LOCAL_BIN" 2>/dev/null || true
    echo "fleet stopped."
}
trap cleanup INT TERM EXIT

# push + run on each host independently, prefixing its output with the host
for h in "${HOSTS[@]}"; do
    target_host="$(ssh_target "$h")"
    port="$(ssh_port "$h")"
    ssh_port_opt=(); scp_port_opt=()
    if [[ -n "$port" ]]; then ssh_port_opt=(-p "$port"); scp_port_opt=(-P "$port"); fi

    (
        # push the binary, then run it; all output is prefixed with [host]
        if ! scp "${SSH_OPTS_ARR[@]}" "${scp_port_opt[@]}" "$LOCAL_BIN" "$target_host:$REMOTE_BIN" >/dev/null 2>&1; then
            echo "[$target_host] scp failed — skipping"
            exit 0
        fi
        ssh "${SSH_OPTS_ARR[@]}" "${ssh_port_opt[@]}" "$target_host" \
            "chmod +x '$REMOTE_BIN' && '$REMOTE_BIN' $DEMON_ARGS_STR '$TARGET'" </dev/null 2>&1 \
            | sed "s/^/[$target_host] /"
    ) &
    PIDS+=("$!")
done

echo "[fleet] launched on ${#HOSTS[@]} hosts — ctrl+c stops all of them"
echo ""

# wait for all host streamers; ctrl+c trips the trap and tears the fleet down
wait
