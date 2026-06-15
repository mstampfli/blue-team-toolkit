#!/usr/bin/env bash
# Per-host triage, core live-state collection.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

OUT="$OUTPUT_DIR/triage-$(hostname)-$(date +%F-%H%M).txt"
log "TRIAGE start -> $OUT"

run() {
  local label="$1"; shift
  {
    echo
    echo "===== $label ====="
    echo "\$ $*"
    "$@" 2>&1
    echo "[exit $?]"
  } >> "$OUT"
}

# --- Tool dispatch (uses run_silent heartbeat from common.sh) ---
echo "[triage] dispatching to installed tools first..." | tee -a "$OUT"

if command -v lynis >/dev/null 2>&1; then
  L="$OUTPUT_DIR/lynis-triage-$(date +%F-%H%M).log"
  run_silent "lynis" "$L" sudo lynis audit system --quick --no-colors
  echo "===== lynis (see $L) =====" >> "$OUT"
fi

if [[ -f "$TOOLS_DIR/linpeas.sh" ]] && confirm_box "Run LinPEAS now (3-15 min, full privesc surface)?"; then
  LP="$OUTPUT_DIR/linpeas-$(date +%F-%H%M).txt"
  run_silent "linpeas" "$LP" bash "$TOOLS_DIR/linpeas.sh" -a
  echo "===== linpeas (see $LP) =====" >> "$OUT"
fi

if command -v rkhunter >/dev/null 2>&1; then
  RK="$OUTPUT_DIR/rkhunter-$(date +%F-%H%M).log"
  run_silent "rkhunter" "$RK" sudo rkhunter --check --skip-keypress --report-warnings-only
  echo "===== rkhunter (see $RK) =====" >> "$OUT"
  grep -E 'Warning' "$RK" 2>/dev/null | while IFS= read -r line; do
    record_finding "rkhunter_warning" "$(echo "$line" | head -c 200)"
  done
fi

if command -v chkrootkit >/dev/null 2>&1; then
  CK="$OUTPUT_DIR/chkrootkit-$(date +%F-%H%M).log"
  run_silent "chkrootkit" "$CK" sudo chkrootkit -q
  echo "===== chkrootkit (see $CK) =====" >> "$OUT"
  grep -E 'INFECTED|Vulnerable' "$CK" 2>/dev/null | while IFS= read -r line; do
    record_finding "chkrootkit_alert" "$(echo "$line" | head -c 200)"
  done
fi

echo | tee -a "$OUT"
echo "[triage] tool dispatch done; collecting raw state..." | tee -a "$OUT"

run "uname -a"               uname -a
run "uptime"                 uptime
run "logged in / recent"     bash -c 'who; echo "---"; w; echo "---"; last -F | head -50'
run "listening sockets"      bash -c 'ss -tulpan 2>/dev/null || netstat -tulpan'
run "established outbound"   bash -c 'ss -tan state established 2>/dev/null'
run "process tree"           bash -c 'ps auxf'
run "deleted-binary procs"   bash -c 'ls -la /proc/*/exe 2>/dev/null | grep deleted'
run "cron"                   bash -c 'ls -la /etc/cron* /var/spool/cron/ 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do out=$(crontab -u "$u" -l 2>/dev/null); [ -n "$out" ] && echo "--- $u ---" && echo "$out"; done'
run "systemd enabled"        bash -c 'systemctl list-unit-files --state=enabled 2>/dev/null'
run "systemd recent units"   bash -c 'find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /etc/hostname 2>/dev/null'
run "ssh authorized_keys"    bash -c 'find / -name authorized_keys 2>/dev/null'
run "ssh keys content"       bash -c 'for f in $(find /root/.ssh /home/*/.ssh -name authorized_keys 2>/dev/null); do echo "--- $f ---"; cat "$f"; done'
run "sudoers"                bash -c 'cat /etc/sudoers; echo "---"; ls -la /etc/sudoers.d/; echo "---"; cat /etc/sudoers.d/* 2>/dev/null'
run "SUID binaries"          bash -c 'find / -perm -4000 -type f 2>/dev/null'
run "world-writable in path" bash -c 'find /usr /etc /opt /var -perm -0002 -type f 2>/dev/null | head -100'
run "recent /etc mods"       bash -c 'find /etc /usr/bin /usr/sbin /usr/local /lib /lib64 -mtime -7 -type f 2>/dev/null'
run "kernel modules"         lsmod
run "ld.so.preload"          bash -c 'cat /etc/ld.so.preload 2>/dev/null || echo "(empty)"'
run "PAM modules"            bash -c 'find /lib/security /lib64/security /usr/lib/security 2>/dev/null; ls -la /etc/pam.d/'
run "users with UID 0"       bash -c 'awk -F: "\$3==0 {print}" /etc/passwd'
run "empty passwords"        bash -c 'awk -F: "\$2==\"\" {print \$1}" /etc/shadow 2>/dev/null'
run "tmp executables"        bash -c 'find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null'
run "hidden in tmp"          bash -c 'find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null'
run "printer.exe hunt"       bash -c 'find / -name "printer*" -type f 2>/dev/null | grep -vE "/proc|/sys|/snap|/var/cache"'
run "Docker privileged"      bash -c 'command -v docker >/dev/null && docker ps --filter "is-task=false" --format "table {{.Names}}\t{{.Image}}\t{{.Command}}" 2>/dev/null'
run "package verify"         bash -c 'if command -v debsums >/dev/null; then debsums -c 2>/dev/null | head -100; elif command -v rpm >/dev/null; then rpm -Va 2>/dev/null | head -100; else echo "(no debsums/rpm)"; fi'

log "TRIAGE done -> $OUT"
info_box "Triage written to:\n$OUT\n\nReview, then copy to your evidence store.\n\nFor follow-up hunts, see option 4."
