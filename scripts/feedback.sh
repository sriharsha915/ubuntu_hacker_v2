#!/usr/bin/env bash
#
# feedback.sh — the manual loop's bridge to your LLM.
#
# Run any command; this captures its stdout, stderr and exit code and prints
# a ready-to-paste block for ChatGPT / Claude / your LLM of choice. The block
# is also saved under engagements/feedback/ for your records.
#
#   ./scripts/feedback.sh curl -s 'http://127.0.0.1:5000/search?q=<svg onload=alert(1)>'
#   ./scripts/feedback.sh sqlmap -u 'http://127.0.0.1:5000/login' --batch
#
# Then paste the output into your LLM and ask for the next move. Feed the LLM's
# suggested command back through feedback.sh again — that is the loop.
#
set -uo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${FEEDBACK_DIR:-$here/engagements/feedback}"
mkdir -p "$out_dir"
stamp="$(date +%Y%m%d-%H%M%S)"
out_file="$out_dir/cmd-$stamp.txt"

tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "$tmp_out" "$tmp_err"' EXIT

# Run the command, capturing both streams separately.
"$@" >"$tmp_out" 2>"$tmp_err"
code=$?

block=$(cat <<EOF
================= FEED THIS BACK TO THE LLM =================
## Command
$*

## Exit code
$code

## STDOUT
$(cat "$tmp_out")

## STDERR
$(cat "$tmp_err")

## Ask
The command above ran during an AUTHORIZED security test. Given this result,
what is the single best next command or payload to try? Reply with the next
concrete step. If the component appears safe, reply SAFE and explain why.
============================================================
EOF
)

printf '%s\n' "$block" | tee "$out_file"
echo "[saved $out_file]" >&2
exit "$code"
