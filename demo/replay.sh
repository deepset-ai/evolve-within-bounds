#!/usr/bin/env bash
# Play back the run demo/record.sh recorded, in this terminal, as it ran.
#   demo/replay.sh          at the speed it was recorded
#   demo/replay.sh 2        twice as fast
#   demo/replay.sh 2 20     twice as fast, and never pausing longer than 20 seconds between outputs
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=runs/demo/recording
if [[ ! -s "$OUT/timing.log" ]]; then
  echo "no recording yet: demo/record.sh" >&2
  exit 1
fi
clear
scriptreplay --log-timing "$OUT/timing.log" --log-out "$OUT/session.log" --divisor "${1:-1}" ${2:+--maxdelay "$2"}
