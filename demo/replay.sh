#!/usr/bin/env bash
# Play back the run demo/record.sh recorded (demo/recording), in this terminal, as it ran.
#   demo/replay.sh          at the speed it was recorded
#   demo/replay.sh 2        twice as fast
#   demo/replay.sh 2 20     twice as fast, and never pausing longer than 20 seconds between outputs
# As in the live run, it stops at the approval prompt until you type yes. It needs only Python 3's standard library, so
# the recording plays back on any machine with the repository.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=demo/recording
if [[ ! -s "$OUT/timing.log" ]]; then
  echo "no recording yet: demo/record.sh" >&2
  exit 1
fi
clear 2>/dev/null || true
exec python3 - "$OUT" "${1:-1}" "${2:-0}" <<'EOF'
"""
Replay a `script` recording: timing.log gives, for each chunk of session.log, the wait before it and its size.

In a terminal, the replay stops at the approval prompt until you type yes, and skips the answer the recording holds (it
was recorded with --yes). Without a terminal, it plays the recording as it is.
"""
import sys
import time
from pathlib import Path

PROMPT = b"Type 'yes' to approve: "
out, speed, max_pause = Path(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
data = (out / "session.log").read_bytes()
data = data[data.index(b"\n") + 1 :]  # the first line is the header script writes
try:
    terminal = open("/dev/tty", "r")  # stdin holds this program
except OSError:
    terminal = None
prompt_end = data.find(PROMPT)
prompt_end = prompt_end + len(PROMPT) if prompt_end >= 0 and terminal else -1
answer_end = data.find(b"\n", prompt_end) + 1 if prompt_end >= 0 else -1


def write(start: int, end: int) -> None:
    sys.stdout.buffer.write(data[start:end])
    sys.stdout.buffer.flush()


def ask() -> None:
    while terminal.readline().strip().lower() != "yes":
        sys.stdout.buffer.write(b"    " + PROMPT)
        sys.stdout.buffer.flush()


position, asked = 0, False
try:
    for line in (out / "timing.log").read_text().splitlines():
        delay, size = line.split()
        pause = float(delay) / speed
        time.sleep(min(pause, max_pause) if max_pause > 0 else pause)
        start, end = position, position + int(size)
        if not asked and prompt_end >= 0 and start < prompt_end <= end:
            write(start, prompt_end)
            ask()
            asked = True
        if asked:
            start = max(start, answer_end)  # the recorded answer: the typed one is already on the screen
        write(start, end)
        position = end
except KeyboardInterrupt:
    pass
finally:
    sys.stdout.write("\033[0m\n")
EOF
