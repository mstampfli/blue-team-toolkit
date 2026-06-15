#!/usr/bin/env bash
# Blue Team Toolkit, Linux entry point
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOOLKIT_DIR="$SCRIPT_DIR"
export OUTPUT_DIR="$SCRIPT_DIR/output"
export TOOLS_DIR="$SCRIPT_DIR/tools"
export LOG_FILE="$OUTPUT_DIR/toolkit.log"
mkdir -p "$OUTPUT_DIR" "$TOOLS_DIR"

# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/linux/common.sh"

for c in whiptail jq curl; do
  command -v "$c" >/dev/null 2>&1 || die "$c not found. Install with: sudo apt install -y whiptail jq curl"
done

main_menu() {
  while true; do
    choice=$(whiptail --title "Blue Team Toolkit, Linux" \
      --menu "Workflow order: 1 install, 2 map, 3 recommend, 4 harden, then 5/6 triage/hunt." 23 92 14 \
      "1" "Install / download tools      (from tools.json)" \
      "2" "Map / discover this host      (writes facts.json; lynis, linpeas, nmap)" \
      "3" "Recommendations punch list    (reads facts.json, prioritized P0/P1/P2)" \
      "4" "Hardening checklist           (semi-auto, dry-run by default)" \
      "5" "Per-host triage               (live state; dispatches lynis + linpeas)" \
      "6" "Backdoor / persistence hunt   (dispatches loki / yara / rkhunter)" \
      "7" "Network recon                 (internal nmap + external Shodan / DNS)" \
      "8" "Findings history              (persistent across runs)" \
      "9" "Security report card          (graded HTML + Markdown from facts + findings)" \
      "L" "View action log" \
      "Q" "Quit" \
      3>&1 1>&2 2>&3) || exit 0
    case "$choice" in
      1) bash "$SCRIPT_DIR/lib/linux/installer.sh" ;;
      2) bash "$SCRIPT_DIR/lib/linux/map.sh" ;;
      3) bash "$SCRIPT_DIR/lib/linux/recommend.sh" ;;
      4) bash "$SCRIPT_DIR/lib/linux/harden.sh" ;;
      5) bash "$SCRIPT_DIR/lib/linux/triage.sh" ;;
      6) bash "$SCRIPT_DIR/lib/linux/hunt.sh" ;;
      7) bash "$SCRIPT_DIR/lib/linux/recon.sh" ;;
      8) bash "$SCRIPT_DIR/lib/linux/findings.sh" ;;
      9) bash "$SCRIPT_DIR/lib/linux/report.sh" ;;
      L) [[ -f "$LOG_FILE" ]] && less +G "$LOG_FILE" || whiptail --msgbox "No log entries yet." 8 40 ;;
      Q) exit 0 ;;
    esac
  done
}

main_menu
