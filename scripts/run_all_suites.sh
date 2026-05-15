#!/usr/bin/env bash
#
# run_all_suites.sh — vc-pqc unified test & benchmark orchestrator
#
# Opens each selected suite in a separate macOS Terminal.app window (or
# iTerm2 tab), streams output to per-suite log files, and shows a live
# status board in the originating terminal.
#
# Compatible with bash 3.2+ (macOS system shell).
#
# USAGE
#   ./scripts/run_all_suites.sh [OPTIONS]
#
# OPTIONS
#   --dry-run               Print commands without executing anything
#   --suites=S1,S2,...      Run only the listed suite IDs (comma-separated)
#   --list                  Print all available suite IDs and exit
#   --iterm                 Open sessions in iTerm2 instead of Terminal.app
#   --no-new-windows        Run suites sequentially in this terminal
#   --results-dir=DIR       Override the output directory
#   --no-status             Skip the live status board after launching windows
#   --help                  Show this message
#
# SUITE IDs
#   snark_harness       Aurora SNARK harness tests                  (~5 min)
#   euf_cma             EUF-CMA forgery resistance tests            (~3 min)
#   pp3_policy_fast     PP3 policy evaluation — fast path           (~1 min)
#   loquat_table3       Loquat Table-3 Griffin benchmark            (~10 min)
#   d3_unlinkability    D3 unlinkability — Aurora proving path      (~30 min)
#   pp2_revocation      PP2 revocation enforcement — Aurora proving (~30 min)
#   pp3_policy_full     PP3 policy inside Aurora proof              (~30 min)
#   zkvm_dev            zkVM parameter sweep — dev/execute-only     (~60 min)
#   zkvm_full           zkVM parameter sweep — full STARK proving   (~10 h)
#   bench_runner        Full benchmark suite B1–B7                  (~3 h)
#
# EXAMPLES
#   # Preview what would run (no execution)
#   ./scripts/run_all_suites.sh --dry-run --suites=snark_harness,euf_cma,pp3_policy_fast
#
#   # Run fast suites only
#   ./scripts/run_all_suites.sh --suites=snark_harness,euf_cma,pp3_policy_fast,loquat_table3
#
#   # Full overnight run
#   ./scripts/run_all_suites.sh
#
#   # zkVM dev sweep in this terminal (no new windows)
#   ./scripts/run_all_suites.sh --suites=zkvm_dev --no-new-windows
#
# NOTES
# - zkvm_dev uses RISC0_DEV_MODE=1 (execute-only, ~15 s/combo, no proof).
# - zkvm_full generates real succinct STARK receipts (~5–30 min/combo).
# - Aurora-proving-path tests are #[ignore] in Rust; this script passes
#   --ignored to cargo test to un-skip them.
# - All output is also written to <results-dir>/logs/<suite>.log.

# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THESIS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ─────────────────────────────────────────────────────────────────────────────
# Suite registry  (bash 3.2 — no associative arrays)
#
# Parallel indexed arrays; use suite_idx <id> to get the position.
# ─────────────────────────────────────────────────────────────────────────────

#           id                          label                                         workdir   env_prefix        command                                                     mins
_REG_IDS=(  "snark_harness"             "euf_cma"                "pp3_policy_fast"  "loquat_table3"            "d3_unlinkability"             "pp2_revocation"              "pp3_policy_full"              "zkvm_dev"             "zkvm_full"            "bench_runner"       )
_REG_LABELS=(
    "Aurora SNARK harness (snark_harness.rs)"
    "EUF-CMA forgery resistance (euf_cma.rs)"
    "PP3 policy evaluation — fast path"
    "Loquat Table-3 Griffin benchmark"
    "D3 unlinkability — Aurora proving path"
    "PP2 revocation enforcement — Aurora proving path"
    "PP3 policy inside Aurora proof — Aurora proving path"
    "zkVM parameter sweep — dev/execute-only mode"
    "zkVM parameter sweep — full STARK proving"
    "Full benchmark suite B1-B7 via bench_runner"
)
_REG_WORKDIRS=(
    ""        # snark_harness   → THESIS_DIR
    ""        # euf_cma
    ""        # pp3_policy_fast
    ""        # loquat_table3
    ""        # d3_unlinkability
    ""        # pp2_revocation
    ""        # pp3_policy_full
    "zkvm"    # zkvm_dev        → THESIS_DIR/zkvm
    "zkvm"    # zkvm_full
    ""        # bench_runner
)
_REG_ENVS=(
    ""                  # snark_harness
    ""                  # euf_cma
    ""                  # pp3_policy_fast
    ""                  # loquat_table3
    ""                  # d3_unlinkability
    ""                  # pp2_revocation
    ""                  # pp3_policy_full
    "RISC0_DEV_MODE=1"  # zkvm_dev
    ""                  # zkvm_full
    ""                  # bench_runner
)
_REG_CMDS=(
    "cargo test --features snark_harness --test snark_harness"
    "cargo test --features euf_cma_harness --test euf_cma"
    "cargo test --test pp3_policy"
    "bash scripts/run_loquat_table3_griffin.sh"
    "cargo test --test d3_unlinkability -- --ignored"
    "cargo test --test pp2_revocation -- --ignored"
    "cargo test --test pp3_policy -- --ignored"
    "cargo run --release -- --json --dev-mode"
    "cargo run --release -- --json"
    "cargo run --release --bin bench_runner"
)
_REG_MINS=(5 3 1 10 30 30 30 60 600 180)

# ── Accessors ────────────────────────────────────────────────────────────────

suite_idx() {
    local id="$1" i
    for i in "${!_REG_IDS[@]}"; do
        if [[ "${_REG_IDS[$i]}" == "$id" ]]; then
            echo "$i"; return 0
        fi
    done
    echo ""; return 1
}
suite_label()   { local i; i=$(suite_idx "$1"); echo "${_REG_LABELS[$i]}"; }
suite_workdir() { local i; i=$(suite_idx "$1"); echo "${_REG_WORKDIRS[$i]}"; }
suite_env()     { local i; i=$(suite_idx "$1"); echo "${_REG_ENVS[$i]}"; }
suite_cmd()     { local i; i=$(suite_idx "$1"); echo "${_REG_CMDS[$i]}"; }
suite_mins()    { local i; i=$(suite_idx "$1"); echo "${_REG_MINS[$i]}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────

DRY_RUN=false
SELECTED_SUITES=()
TERMINAL_APP="Terminal"   # Terminal | iTerm
NO_NEW_WINDOWS=false
RESULTS_DIR="$THESIS_DIR/results/run_$TIMESTAMP"
SHOW_STATUS=true
STATUS_POLL_SECS=5

# ─────────────────────────────────────────────────────────────────────────────
# Colours (disabled when not a tty)
# ─────────────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    R='\033[0m' BOLD='\033[1m'
    GRN='\033[0;32m' RED='\033[0;31m' YLW='\033[0;33m'
    CYN='\033[0;36m' DIM='\033[2m'
else
    R='' BOLD='' GRN='' RED='' YLW='' CYN='' DIM=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# Help / list
# ─────────────────────────────────────────────────────────────────────────────

print_help() {
    sed -n '4,60p' "$0" | sed 's/^# \{0,1\}//'
}

list_suites() {
    printf "%-22s  %-6s  %s\n" "Suite ID" "Est." "Description"
    printf "%-22s  %-6s  %s\n" "--------" "----" "-----------"
    local i
    for i in "${!_REG_IDS[@]}"; do
        printf "%-22s  ~%-4sm  %s\n" \
            "${_REG_IDS[$i]}" "${_REG_MINS[$i]}" "${_REG_LABELS[$i]}"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --dry-run)           DRY_RUN=true ;;
        --iterm)             TERMINAL_APP="iTerm" ;;
        --no-new-windows)    NO_NEW_WINDOWS=true ;;
        --no-status)         SHOW_STATUS=false ;;
        --list)              list_suites; exit 0 ;;
        --help|-h)           print_help; exit 0 ;;
        --suites=*)
            IFS=',' read -ra SELECTED_SUITES <<< "${arg#--suites=}"
            ;;
        --results-dir=*)
            RESULTS_DIR="${arg#--results-dir=}"
            ;;
        *)
            echo "Unknown argument: $arg  (try --help)" >&2
            exit 1
            ;;
    esac
done

# Default: run all suites
if [[ ${#SELECTED_SUITES[@]} -eq 0 ]]; then
    SELECTED_SUITES=("${_REG_IDS[@]}")
fi

# Validate suite IDs
for id in "${SELECTED_SUITES[@]}"; do
    if ! suite_idx "$id" > /dev/null 2>&1; then
        echo "Unknown suite ID: '$id'  (run --list to see options)" >&2
        exit 1
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Dry-run preview
# ─────────────────────────────────────────────────────────────────────────────

if $DRY_RUN; then
    echo -e "${BOLD}DRY RUN — nothing will be executed${R}"
    echo ""
    printf "  %-20s  %s\n" "Results dir:" "$RESULTS_DIR"
    printf "  %-20s  %s\n" "Terminal:" "$TERMINAL_APP"
    printf "  %-20s  %s\n" "New windows:" "$( $NO_NEW_WINDOWS && echo 'no (sequential)' || echo 'yes (osascript)' )"
    echo ""
    printf "%-22s  %-8s  %-10s  %s\n" "Suite" "Est." "Workdir" "Command"
    printf "%-22s  %-8s  %-10s  %s\n" "-----" "----" "-------" "-------"
    for id in "${SELECTED_SUITES[@]}"; do
        local_wd="$(suite_workdir "$id")"; [[ -z "$local_wd" ]] && local_wd="<root>"
        env_part="$(suite_env "$id")"; [[ -n "$env_part" ]] && env_part="$env_part "
        printf "%-22s  ~%-6sm  %-10s  %s%s\n" \
            "$id" "$(suite_mins "$id")" "$local_wd" "$env_part" "$(suite_cmd "$id")"
    done
    echo ""
    echo "Logs would be written to: $RESULTS_DIR/logs/<suite>.log"
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Create results layout
# ─────────────────────────────────────────────────────────────────────────────

mkdir -p \
    "$RESULTS_DIR/logs" \
    "$RESULTS_DIR/status" \
    "$RESULTS_DIR/wrappers"

echo -e "${BOLD}Results directory:${R} $RESULTS_DIR"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Wrapper script generator
#
# Each suite runs inside an auto-generated wrapper that:
#   1. Redirects all output to the log file (via tee)
#   2. Sets the Terminal window title
#   3. Writes status markers (running / done:0 / failed:N) to status/
# ─────────────────────────────────────────────────────────────────────────────

generate_wrapper() {
    local id="$1"
    local label; label="$(suite_label "$id")"
    local rel_wd; rel_wd="$(suite_workdir "$id")"
    local env_prefix; env_prefix="$(suite_env "$id")"
    local cmd; cmd="$(suite_cmd "$id")"
    local log="$RESULTS_DIR/logs/${id}.log"
    local status_file="$RESULTS_DIR/status/${id}"

    if [[ -n "$rel_wd" ]]; then
        local workdir="$THESIS_DIR/$rel_wd"
    else
        local workdir="$THESIS_DIR"
    fi

    local full_cmd
    if [[ -n "$env_prefix" ]]; then
        full_cmd="$env_prefix $cmd"
    else
        full_cmd="$cmd"
    fi

    local wrapper="$RESULTS_DIR/wrappers/${id}.sh"

    # Write the wrapper using printf to avoid heredoc quoting pitfalls.
    # Variables are expanded here (during generation); the wrapper itself
    # uses only plain sh constructs so it stays bash 3.2 compatible.
    printf '%s\n' '#!/usr/bin/env bash' 'set -uo pipefail' '' \
        "# Auto-generated wrapper for suite: $id" \
        "SUITE_ID='$id'" \
        "LOG_FILE='$log'" \
        "STATUS_FILE='$status_file'" \
        "WORK_DIR='$workdir'" \
        "FULL_CMD='$full_cmd'" \
        "LABEL='$label'" \
        '' \
        '# Tee all output to the log file.' \
        'exec > >(tee -a "$LOG_FILE") 2>&1' \
        '' \
        '# Set the Terminal window / tab title.' \
        "printf '\\033]0;vc-pqc | %s\\007' \"\$SUITE_ID\"" \
        '' \
        'divider() { printf "%0.s-" $(seq 1 68); echo; }' \
        '' \
        'echo ""' \
        'divider' \
        'printf "  vc-pqc thesis -- suite: %s\n" "$SUITE_ID"' \
        'printf "  %s\n" "$LABEL"' \
        'printf "  Started : %s\n" "$(date +'"'"'%Y-%m-%d %H:%M:%S'"'"')"' \
        'printf "  Log     : %s\n" "$LOG_FILE"' \
        'divider' \
        'echo ""' \
        '' \
        'echo "running" > "$STATUS_FILE"' \
        '' \
        'cd "$WORK_DIR"' \
        '' \
        'EXIT_CODE=0' \
        'eval "$FULL_CMD" || EXIT_CODE=$?' \
        '' \
        'echo ""' \
        'divider' \
        'if [ "$EXIT_CODE" -eq 0 ]; then' \
        '    printf "  RESULT : PASSED\n"' \
        '    echo "done:0" > "$STATUS_FILE"' \
        'else' \
        '    printf "  RESULT : FAILED (exit %d)\n" "$EXIT_CODE"' \
        "    echo \"failed:\$EXIT_CODE\" > \"\$STATUS_FILE\"" \
        'fi' \
        'printf "  Finished: %s\n" "$(date +'"'"'%Y-%m-%d %H:%M:%S'"'"')"' \
        'printf "  Log     : %s\n" "$LOG_FILE"' \
        'divider' \
        'echo ""' \
        '' \
        'echo "Press Enter to close this window..."' \
        'read -r || true' \
        > "$wrapper"

    chmod +x "$wrapper"
    echo "$wrapper"
}

# ─────────────────────────────────────────────────────────────────────────────
# Generate all wrappers up front
# ─────────────────────────────────────────────────────────────────────────────

declare -a SUITE_WRAPPERS=()
for id in "${SELECTED_SUITES[@]}"; do
    SUITE_WRAPPERS+=("$(generate_wrapper "$id")")
done

# ─────────────────────────────────────────────────────────────────────────────
# Terminal launch helpers
# ─────────────────────────────────────────────────────────────────────────────

open_terminal_app_window() {
    local wrapper="$1"
    local title="$2"
    # "do script" without "in" always creates a new Terminal.app window.
    osascript - "$wrapper" "$title" <<'APPLESCRIPT'
on run argv
    set wrapperPath to item 1 of argv
    set windowTitle to item 2 of argv
    tell application "Terminal"
        activate
        set newWin to do script ("bash " & wrapperPath)
        delay 0.2
        set custom title of front window to windowTitle
        set number of rows of front window to 42
        set number of columns of front window to 120
    end tell
end run
APPLESCRIPT
}

open_iterm_tab() {
    local wrapper="$1"
    osascript - "$wrapper" <<'APPLESCRIPT'
on run argv
    set wrapperPath to item 1 of argv
    tell application "iTerm2"
        activate
        tell current window
            set newTab to (create tab with default profile)
            tell current session of newTab
                write text ("bash " & wrapperPath)
            end tell
        end tell
    end tell
end run
APPLESCRIPT
}

# ─────────────────────────────────────────────────────────────────────────────
# Launch all selected suites
# ─────────────────────────────────────────────────────────────────────────────

LAUNCH_START="$(date +%s)"

echo -e "${BOLD}Launching ${#SELECTED_SUITES[@]} suite(s)...${R}"
echo ""

idx=0
for id in "${SELECTED_SUITES[@]}"; do
    wrapper="${SUITE_WRAPPERS[$idx]}"
    title="vc-pqc | $id"
    label="$(suite_label "$id")"
    mins="$(suite_mins "$id")"
    idx=$(( idx + 1 ))

    # Mark as pending before launch
    echo "pending" > "$RESULTS_DIR/status/$id"

    if $NO_NEW_WINDOWS; then
        echo -e "  ${CYN}>${R} ${BOLD}$id${R}  ($label)"
        bash "$wrapper"
    else
        echo -e "  ${CYN}>${R} ${BOLD}$id${R}  ~${mins}m  $label"
        case "$TERMINAL_APP" in
            iTerm|iterm|iTerm2) open_iterm_tab "$wrapper" ;;
            *)                  open_terminal_app_window "$wrapper" "$title" ;;
        esac
        # Brief delay so the window opens before launching the next one.
        sleep 0.5
    fi
done

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Status helpers
# ─────────────────────────────────────────────────────────────────────────────

read_status() {
    local sf="$RESULTS_DIR/status/$1"
    if [[ -f "$sf" ]]; then cat "$sf"; else echo "pending"; fi
}

status_icon() {
    case "$1" in
        done:0)   echo -e "${GRN}passed${R}" ;;
        failed:*) echo -e "${RED}FAILED ($1)${R}" ;;
        running)  echo -e "${YLW}running${R}" ;;
        pending)  echo -e "${DIM}pending${R}" ;;
        *)        echo -e "${DIM}$1${R}" ;;
    esac
}

all_done() {
    local id
    for id in "${SELECTED_SUITES[@]}"; do
        case "$(read_status "$id")" in
            done:*|failed:*) ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# Number of lines to clear when redrawing the status board.
BOARD_LINES=$(( ${#SELECTED_SUITES[@]} + 4 ))

print_status_board() {
    local elapsed=$(( $(date +%s) - LAUNCH_START ))
    local hh=$(( elapsed / 3600 ))
    local mm=$(( (elapsed % 3600) / 60 ))
    local ss=$(( elapsed % 60 ))
    local ts
    printf -v ts "%02d:%02d:%02d" "$hh" "$mm" "$ss"

    echo -e "${BOLD}vc-pqc suite status${R}  [elapsed: $ts]  $(date '+%H:%M:%S')"
    printf "%-24s  %-6s  %-20s  %s\n" "Suite" "Est." "Status" "Last log line"
    printf "%-24s  %-6s  %-20s  %s\n" "-----" "----" "------" "-------------"

    local id
    for id in "${SELECTED_SUITES[@]}"; do
        local s; s="$(read_status "$id")"
        local icon; icon="$(status_icon "$s")"
        local log="$RESULTS_DIR/logs/${id}.log"
        local tail_line=""
        if [[ -f "$log" ]]; then
            tail_line="$(tail -n1 "$log" 2>/dev/null | cut -c1-55 || true)"
        fi
        printf "%-24s  ~%-4sm  " "$id" "$(suite_mins "$id")"
        echo -ne "$icon"
        printf "  %s\n" "$tail_line"
    done
}

write_final_summary() {
    local summary="$RESULTS_DIR/run_summary.txt"
    local any_failed=false
    {
        echo "vc-pqc run summary — $(date)"
        echo "Results directory: $RESULTS_DIR"
        echo ""
        printf "%-24s  %-6s  %s\n" "Suite" "Est." "Status"
        printf "%-24s  %-6s  %s\n" "-----" "----" "------"
        for id in "${SELECTED_SUITES[@]}"; do
            local s; s="$(read_status "$id")"
            printf "%-24s  ~%-4sm  %s\n" "$id" "$(suite_mins "$id")" "$s"
            case "$s" in failed:*) any_failed=true ;; esac
        done
        echo ""
        if $any_failed; then echo "OVERALL: some suites FAILED"
        else                  echo "OVERALL: all suites passed"
        fi
        local elapsed=$(( $(date +%s) - LAUNCH_START ))
        printf "Total wall time: %dh %dm %ds\n" \
            $(( elapsed / 3600 )) $(( (elapsed % 3600) / 60 )) $(( elapsed % 60 ))
    } > "$summary"
    echo "$summary"
}

# ─────────────────────────────────────────────────────────────────────────────
# Live status board  (only for multi-window mode)
# ─────────────────────────────────────────────────────────────────────────────

if ! $NO_NEW_WINDOWS && $SHOW_STATUS; then
    echo -e "${BOLD}Watching suites — Ctrl-C to stop watching (suites keep running in their windows)${R}"
    echo ""

    trap '
        echo ""
        echo "Monitoring interrupted — suites are still running in their windows."
        write_final_summary > /dev/null
        exit 0
    ' INT TERM

    first_draw=true
    while ! all_done; do
        if $first_draw; then
            first_draw=false
        else
            # Move cursor up to overwrite the previous board.
            printf '\033[%dA' "$BOARD_LINES"
        fi
        print_status_board
        sleep "$STATUS_POLL_SECS"
    done

    # Final redraw after all suites complete.
    printf '\033[%dA' "$BOARD_LINES"
    print_status_board
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────

SUMMARY_FILE="$(write_final_summary)"

echo -e "${BOLD}Run complete.${R}"
echo ""

any_failed=false
for id in "${SELECTED_SUITES[@]}"; do
    s="$(read_status "$id")"
    printf "  %-24s  " "$id"
    status_icon "$s"
    case "$s" in failed:*) any_failed=true ;; esac
done

echo ""
echo -e "${BOLD}Logs:${R}    $RESULTS_DIR/logs/"
echo -e "${BOLD}Summary:${R} $SUMMARY_FILE"
echo ""

if $any_failed; then
    echo -e "${RED}${BOLD}Some suites FAILED.${R}  Check logs above."
    exit 1
else
    echo -e "${GRN}${BOLD}All monitored suites passed.${R}"
    exit 0
fi
