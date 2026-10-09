# aliases.sh — source this for seamless shortcuts.
#
#   source scripts/aliases.sh
#
# then use:
#   al-target      launch the demo target
#   al-xss         run the reflected-xss scenario
#   al-sqli        run the sqli-login scenario
#   attackloop …   the raw CLI (pass any flags)
#   al-feedback …  capture a command's output for your LLM
#   al-selfcheck   show which optional deps are installed

_AL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

alias attackloop="'$_AL_ROOT/scripts/run.sh'"
alias al-target="'$_AL_ROOT/scripts/start_target.sh'"
alias al-xss="'$_AL_ROOT/scripts/run.sh' --scenario reflected-xss"
alias al-sqli="'$_AL_ROOT/scripts/run.sh' --scenario sqli-login"
alias al-feedback="'$_AL_ROOT/scripts/feedback.sh'"
alias al-selfcheck="'$_AL_ROOT/scripts/run.sh' --selfcheck"

echo "[attack-loop] aliases loaded: attackloop, al-target, al-xss, al-sqli, al-feedback, al-selfcheck"
