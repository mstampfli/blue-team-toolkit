#!/usr/bin/env bash
# Blue Team Toolkit — Linux entry point
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
    choice=$(whiptail --title "Blue Team Toolkit — Linux" \
      --menu "Suggested order: 1 → 6 → 7 → 3 → 2/4. Section refs in parens:" 22 90 13 \
      "1" "Install / Download Tools     (§R)" \
      "6" "Map / Discover this host     (writes facts.json; uses lynis, linpeas, nmap)" \
      "7" "Recommendations punch list   (reads facts.json, prioritized P0/P1/P2)" \
      "3" "Hardening Checklist          (§J semi-auto, dry-run default)" \
      "2" "Per-host Triage              (§I; dispatches lynis + linpeas if installed)" \
      "4" "Backdoor Hunt                (§M / §A; dispatches loki/yara/rkhunter)" \
      "9" "Network Recon                (§H; internal nmap + external Shodan/DNS)" \
      "8" "Findings history             (persistent across runs)" \
      "5" "View action log" \
      "Q" "Quit" \
      3>&1 1>&2 2>&3) || exit 0
    case "$choice" in
      1) bash "$SCRIPT_DIR/lib/linux/installer.sh" ;;
      2) bash "$SCRIPT_DIR/lib/linux/triage.sh" ;;
      3) bash "$SCRIPT_DIR/lib/linux/harden.sh" ;;
      4) bash "$SCRIPT_DIR/lib/linux/hunt.sh" ;;
      5) [[ -f "$LOG_FILE" ]] && less +G "$LOG_FILE" || whiptail --msgbox "No log entries yet." 8 40 ;;
      6) bash "$SCRIPT_DIR/lib/linux/map.sh" ;;
      7) bash "$SCRIPT_DIR/lib/linux/recommend.sh" ;;
      8) bash "$SCRIPT_DIR/lib/linux/findings.sh" ;;
      9) bash "$SCRIPT_DIR/lib/linux/recon.sh" ;;
      Q) exit 0 ;;
    esac
  done
}

main_menu
