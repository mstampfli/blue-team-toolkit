#!/usr/bin/env bash
# Hardening checklist — semi-auto with dry-run by default.
# Each step shows current state, the apply command, and a rollback hint.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

mode=$(whiptail --title "Hardening mode" --menu "How to apply changes?" 15 78 4 \
  "DRY"  "Dry-run (print only — recommended first pass)" \
  "ASK"  "Apply with per-step confirmation (semi-auto)" \
  "QUIT" "Back to menu" \
  3>&1 1>&2 2>&3) || exit 0

case "$mode" in
  DRY)  DRY_RUN=1 ;;
  ASK)  DRY_RUN=0 ;;
  QUIT) exit 0 ;;
esac
log "HARDEN start (mode=$mode)"

# Format: label|check|apply|rollback
ITEMS=(
"SSH: disable root login|grep -E '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo '(default = permitted)'|sudo sed -i 's/^#*[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh|Restore /etc/ssh/sshd_config from backup, reload ssh"

"SSH: disable password auth (key-only)|grep -E '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo '(default = yes)'|sudo sed -i 's/^#*[[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh|sed back to yes, reload ssh"

"auditd installed + Neo23x0 ruleset|systemctl is-active auditd 2>/dev/null || echo 'inactive'|sudo apt-get install -y auditd && sudo curl -fsSL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -o /etc/audit/rules.d/audit.rules && sudo augenrules --load && sudo systemctl enable --now auditd|sudo rm /etc/audit/rules.d/audit.rules and reload"

"fail2ban enabled|systemctl is-active fail2ban 2>/dev/null || echo 'inactive'|sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban|sudo systemctl disable --now fail2ban"

"UFW: default-deny inbound, allow ssh|sudo ufw status verbose 2>/dev/null | head -5|sudo ufw --force enable && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw allow ssh|sudo ufw disable"

"Disable LLMNR (systemd-resolved)|grep -E '^[[:space:]]*LLMNR' /etc/systemd/resolved.conf 2>/dev/null || echo '(default = yes)'|sudo sed -i 's/^#*[[:space:]]*LLMNR=.*/LLMNR=no/' /etc/systemd/resolved.conf && sudo systemctl restart systemd-resolved|Restore resolved.conf, restart"

"Sysctl: drop ICMP redirects + enable kptr_restrict|sysctl net.ipv4.conf.all.accept_redirects kernel.kptr_restrict 2>/dev/null|printf 'net.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nkernel.kptr_restrict=2\nkernel.dmesg_restrict=1\n' | sudo tee /etc/sysctl.d/99-blueteam.conf > /dev/null && sudo sysctl -p /etc/sysctl.d/99-blueteam.conf|sudo rm /etc/sysctl.d/99-blueteam.conf and reboot"

"Remove pkexec setuid bit (PwnKit workaround)|stat -c '%a' /usr/bin/pkexec 2>/dev/null || echo 'not present'|sudo chmod 0755 /usr/bin/pkexec|sudo chmod 4755 /usr/bin/pkexec"

"Disable nf_tables module (CVE-2024-1086 if unused)|lsmod | grep -E '^nf_tables' || echo 'not loaded'|sudo modprobe -r nf_tables 2>/dev/null; echo 'blacklist nf_tables' | sudo tee /etc/modprobe.d/blacklist-nf_tables.conf > /dev/null|sudo rm /etc/modprobe.d/blacklist-nf_tables.conf"

"ClamAV freshclam baseline|systemctl is-active clamav-freshclam 2>/dev/null || echo 'inactive'|sudo apt-get install -y clamav clamav-daemon && sudo systemctl enable --now clamav-freshclam|sudo systemctl disable --now clamav-freshclam"

"Lynis baseline audit (read-only, generates report)|command -v lynis || echo 'not installed'|sudo apt-get install -y lynis && sudo lynis audit system --quick --quiet > '$OUTPUT_DIR/lynis-baseline.txt' 2>&1|N/A — read-only"

"Snapshot package state to baseline|ls $OUTPUT_DIR/baseline-pkgs.txt 2>/dev/null || echo 'no baseline yet'|dpkg -l > '$OUTPUT_DIR/baseline-pkgs.txt' 2>/dev/null && find / -perm -4000 -type f 2>/dev/null > '$OUTPUT_DIR/baseline-suid.txt' && lsmod > '$OUTPUT_DIR/baseline-modules.txt' && echo 'baseline written'|rm baselines"

"Snapshot listening services to baseline|ls $OUTPUT_DIR/baseline-listening.txt 2>/dev/null || echo 'no baseline yet'|ss -tulpan > '$OUTPUT_DIR/baseline-listening.txt' 2>/dev/null && systemctl list-unit-files --state=enabled > '$OUTPUT_DIR/baseline-services.txt' 2>/dev/null && echo 'baseline written'|rm baselines"
)

run_item() {
  local raw="$1"
  IFS='|' read -r label check apply rollback <<< "$raw"

  echo
  echo "----- $label -----"
  printf 'Current : '
  eval "$check" 2>&1 | head -5
  echo "Apply   : $apply"
  echo "Rollback: $rollback"

  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY: would apply: $label"
    echo "[DRY-RUN] not executed."
    read -rp "Press Enter to continue (q=quit)..." ans
    [[ "$ans" =~ ^[qQ] ]] && return 1
    return 0
  fi

  read -rp "Apply this step? [y/N/q] " ans
  case "$ans" in
    y|Y)
      log "APPLY: $label"
      bash -c "$apply" 2>&1 | tee -a "$LOG_FILE"
      log "RESULT exit=${PIPESTATUS[0]}"
      ;;
    q|Q)
      log "QUIT mid-checklist"
      return 1
      ;;
    *)
      log "SKIP: $label"
      echo "skipped."
      ;;
  esac
}

for item in "${ITEMS[@]}"; do
  run_item "$item" || break
done

log "HARDEN done"
info_box "Hardening pass complete (mode=$mode).\n\nLog: $LOG_FILE\n\nReminder: re-run triage (option 2) to verify state after applying."
