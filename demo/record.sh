#!/usr/bin/env bash
# Record a full demo run, with timing, into demo/recording, so demo/replay.sh can play it back if the live run cannot
# happen. The recording is part of the repository: commit it to share it.
#   demo/record.sh                arguments pass through to run_demo.sh (for example --yes)
# `script` gives the run a terminal, so colours and the approval prompt are recorded as the audience would see them.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=demo/recording
# Recorded without a terminal (in the background), the run would lay itself out for 80 columns.
[[ -t 0 ]] || export COLUMNS="${COLUMNS:-110}" LINES="${LINES:-40}"
rm -rf "$OUT"
mkdir -p "$OUT"
passthrough=""
if (($#)); then passthrough=$(printf '%q ' "$@"); fi
script --quiet --return --log-timing "$OUT/timing.log" --log-out "$OUT/session.log" \
  --command "demo/run_demo.sh $passthrough"
# The whole change the optimizer made: the recording shows only its first rows.
cp runs/demo/live/candidate.diff "$OUT/" 2>/dev/null || true
echo
echo "recorded $OUT. Play it back with demo/replay.sh"
