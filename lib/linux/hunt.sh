#!/usr/bin/env bash
# Backdoor hunt — focused on §M checklist + §A planted-backdoor IOCs.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

OUT="$OUTPUT_DIR/hunt-$(hostname)-$(date +%F-%H%M).txt"
log "HUNT start -> $OUT"

H() { echo -e "\n## $1" | tee -a "$OUT"; }
R() { eval "$1" 2>&1 | tee -a "$OUT"; }

# --- Tool dispatch (uses run_silent heartbeat from common.sh) ---
H "Tool dispatch"

LOKI_PY=$(find "$TOOLS_DIR" -maxdepth 3 -type f -iname 'loki.py' 2>/dev/null | head -1)
if [[ -n "$LOKI_PY" ]] && confirm_box "Run Loki IOC scan (10-30 min, scans /)?"; then
  LK="$OUTPUT_DIR/loki-$(date +%F-%H%M).log"
  run_silent "loki" "$LK" sudo python3 "$LOKI_PY" -p / --noprocscan
  echo "Loki report: $LK" | tee -a "$OUT"
  # Loki marks malware hits with 'ALERT' lines
  grep -E '^[A-Z]+:.*ALERT' "$LK" 2>/dev/null | while IFS= read -r line; do
    record_finding "loki_alert" "$(echo "$line" | head -c 200)"
  done
fi

if command -v yara >/dev/null 2>&1; then
  for ruledir in "$TOOLS_DIR/yara-rules" "$TOOLS_DIR/sigma" /usr/share/yara; do
    if [[ -d "$ruledir" ]]; then
      Y="$OUTPUT_DIR/yara-$(date +%F-%H%M).log"
      run_silent "yara" "$Y" bash -c "
        find '$ruledir' -name '*.yar' -o -name '*.yara' 2>/dev/null | while read -r r; do
          sudo yara -r -f \"\$r\" /tmp /var/tmp /dev/shm 2>/dev/null
        done"
      # Each YARA match line is "<rulename> <path>"
      while IFS= read -r line; do
        rule=$(echo "$line" | awk '{print $1}')
        path=$(echo "$line" | awk '{print $2}')
        [[ -n "$rule" && -n "$path" ]] && record_finding "yara_match" "$path" "" "{\"rule\":\"$rule\"}"
      done < "$Y"
      break
    fi
  done
fi

VELO=$(find "$TOOLS_DIR" -maxdepth 2 -type f -iname 'velociraptor*linux*' 2>/dev/null | head -1)
if [[ -n "$VELO" ]] && confirm_box "Run Velociraptor offline collector?"; then
  V="$OUTPUT_DIR/velociraptor-$(date +%F-%H%M).log"
  chmod +x "$VELO"
  run_silent "velociraptor" "$V" sudo "$VELO" artifacts collect \
    Linux.Sys.LastUserLogin Linux.Detection.AnomalousFiles Linux.Network.NetstatEnriched \
    -o "$OUTPUT_DIR/velociraptor-$(date +%F-%H%M).zip"
fi

if command -v unhide >/dev/null 2>&1; then
  U="$OUTPUT_DIR/unhide-$(date +%F-%H%M).log"
  run_silent "unhide" "$U" sudo unhide quick
  # 'Found HIDDEN' lines = real findings
  grep -i 'found hidden' "$U" 2>/dev/null | while IFS= read -r line; do
    record_finding "hidden_proc_or_socket" "$(echo "$line" | head -c 200)"
  done
fi

NUCLEI_BIN=$(ensure_extracted "nuclei*linux*.zip" "nuclei")
if [[ -n "$NUCLEI_BIN" ]] && confirm_box "Run nuclei -t cves/ against http://127.0.0.1 (5-15 min)?"; then
  N="$OUTPUT_DIR/nuclei-$(date +%F-%H%M).log"
  run_silent "nuclei" "$N" "$NUCLEI_BIN" -u http://127.0.0.1 -severity critical,high,medium -nc -silent
  while IFS= read -r line; do
    cve=$(echo "$line" | grep -oE 'CVE-[0-9]{4}-[0-9]+' | head -1)
    sev=$(echo "$line" | grep -oE '\[(critical|high|medium|low)\]' | head -1 | tr -d '[]')
    target=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
    [[ -n "$target" ]] && record_finding "nuclei_cve" "$target" "" "{\"cve\":\"${cve:-unknown}\",\"severity\":\"${sev:-unknown}\",\"confidence\":\"clear\"}"
  done < "$N"
fi

echo | tee -a "$OUT"
echo "[hunt] tool dispatch done; running CLEAR backdoor checks..." | tee -a "$OUT"

# ============================================================
# CLEAR backdoors — high specificity, low false-positive rate
# ============================================================
H "[CLEAR] /etc/passwd — UID 0 user that isn't root"
while IFS=: read -r u _ uid _; do
  [[ "$uid" == "0" && "$u" != "root" ]] && {
    echo "  $u (UID 0)" | tee -a "$OUT"
    record_finding "uid0_non_root_account" "$u" "" '{"confidence":"clear"}'
  }
done < /etc/passwd

H "[CLEAR] empty-password accounts in /etc/shadow"
sudo awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null | while read -r u; do
  [[ -z "$u" ]] && continue
  echo "  $u (no password)" | tee -a "$OUT"
  record_finding "empty_password_user" "$u" "" '{"confidence":"clear"}'
done

H "[CLEAR] cron entries with reverse-shell patterns"
RS_PATTERN='bash -i|/dev/tcp/|nc .*-e|socat |python.*pty\.spawn|/bin/sh -i|perl .*Socket|base64 -d.*\| *(bash|sh)|wget .*\| *sh|curl .*\| *sh'
crons=$(
  ls /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/crontab 2>/dev/null
  for u in $(cut -d: -f1 /etc/passwd); do
    out=$(crontab -u "$u" -l 2>/dev/null) && [[ -n "$out" ]] && echo "USER:$u" && echo "$out"
  done
)
echo "$crons" | grep -inE "$RS_PATTERN" | while IFS= read -r line; do
  echo "  $line" | tee -a "$OUT"
  record_finding "cron_reverse_shell_pattern" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
done

H "[CLEAR] systemd unit ExecStart pointing to writable dirs"
for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
  grep -RnE '^ExecStart=.*(/tmp/|/var/tmp/|/dev/shm/|/home/|/var/cache/)' "$d" 2>/dev/null | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    file=$(echo "$line" | cut -d: -f1)
    record_finding "systemd_unit_writable_dir" "$file" "" '{"confidence":"clear"}'
  done
done

H "[CLEAR] sudoers NOPASSWD entries (excluding default groups)"
{ sudo cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null; } | \
  grep -E 'NOPASSWD' | grep -vE '^\s*#|^Defaults|^%(sudo|admin|wheel)\b' | while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    record_finding "sudoers_nopasswd_entry" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
  done

H "[CLEAR] /etc/ld.so.preload non-empty (LD_PRELOAD rootkit)"
if [[ -s /etc/ld.so.preload ]]; then
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    echo "  $entry" | tee -a "$OUT"
    record_finding "ld_so_preload_entry" "$entry" "" '{"confidence":"clear"}'
  done < /etc/ld.so.preload
else
  echo "  (empty — good)" | tee -a "$OUT"
fi

H "[CLEAR] processes running deleted binary AND with established outbound (Meterpreter signature)"
for pid in $(ls /proc/*/exe 2>/dev/null | xargs -I{} sh -c 'readlink "{}" | grep -q deleted && echo "{}"' 2>/dev/null | grep -oE '/proc/[0-9]+/' | tr -d '/proc/'); do
  has_net=$(ss -tnp state established 2>/dev/null | grep -c "pid=$pid,")
  [[ "$has_net" -gt 0 ]] && {
    cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | head -c 200)
    echo "  PID $pid: $cmd" | tee -a "$OUT"
    record_finding "deleted_exe_with_network" "PID $pid" "" "{\"confidence\":\"clear\",\"cmd\":\"$(echo "$cmd" | sed 's/"/\\"/g')\"}"
  }
done

H "[CLEAR] bashrc / profile sourcing scripts in writable dirs"
grep -lE 'source .*(/tmp/|/dev/shm/|/var/tmp/)|\. .*(/tmp/|/dev/shm/|/var/tmp/)' \
  /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | \
  while IFS= read -r f; do
    echo "  $f" | tee -a "$OUT"
    record_finding "shellrc_sources_writable_dir" "$f" "" '{"confidence":"clear"}'
  done

H "[CLEAR] SSH ForceCommand pointing to writable dir"
grep -E '^ForceCommand .*(/tmp/|/var/tmp/|/dev/shm/)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    record_finding "ssh_forcecommand_writable_dir" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
  done

H "[CLEAR] suspicious listening ports (known malware/C2 defaults)"
SUS_PORTS='4444|4443|1337|31337|6666|6667|8888|9999|12345|54321'
ss -tlnp 2>/dev/null | awk '{print $4, $NF}' | grep -E ":($SUS_PORTS)( |$)" | while IFS= read -r line; do
  echo "  $line" | tee -a "$OUT"
  record_finding "suspicious_listen_port" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
done

H "[CLEAR] services running as root that typically shouldn't"
ps -eo user,pid,comm --no-headers 2>/dev/null | awk '$1=="root"' | \
  awk '$3 ~ /^(nginx|apache2|httpd|mysqld|mariadbd|postgres|redis-server|mongod|node|php-fpm|tomcat|java)$/ {print}' | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    record_finding "service_running_as_root" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
  done

H "[CLEAR] files with non-default capabilities (excluding ping family)"
sudo getcap -r / 2>/dev/null | \
  grep -vE '^$|/(ping|arping|traceroute|tracepath|fping|mtr|gst-ptp-helper|ip)( |$)' | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    file=$(echo "$line" | awk -F' = ' '{print $1}')
    sha=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    record_finding "non_standard_capability" "$line" "$sha" '{"confidence":"maybe"}'
  done

H "[CLEAR] iptables default policies + ACCEPT-from-anywhere rules"
{
  echo "--- INPUT chain (top) ---"; sudo iptables -L INPUT -n -v 2>/dev/null | head -3
  echo "--- FORWARD chain (top) ---"; sudo iptables -L FORWARD -n -v 2>/dev/null | head -3
} | tee -a "$OUT"
sudo iptables -L INPUT 2>/dev/null | head -1 | grep -q 'policy ACCEPT' && {
  echo "  WARN: INPUT policy is ACCEPT (no implicit deny)" | tee -a "$OUT"
  record_finding "iptables_input_policy_accept" "INPUT chain" "" '{"confidence":"clear"}'
}
sudo iptables -L INPUT -n 2>/dev/null | grep -E 'ACCEPT.*0\.0\.0\.0/0' | grep -vE '127\.0\.0\.1|RELATED,ESTABLISHED' | \
  while IFS= read -r line; do
    echo "  ANY-source ACCEPT: $line" | tee -a "$OUT"
    record_finding "iptables_accept_from_anywhere" "$(echo "$line" | head -c 200)" "" '{"confidence":"maybe"}'
  done

H "[CLEAR] UFW rules allowing from anywhere"
sudo ufw status verbose 2>/dev/null | grep -E 'ALLOW IN.*Anywhere' | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    record_finding "ufw_allow_from_anywhere" "$(echo "$line" | head -c 200)" "" '{"confidence":"maybe"}'
  done

H "[CLEAR] Docker containers publishing to 0.0.0.0 (exposed to all interfaces)"
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|::' | \
    while IFS= read -r line; do
      echo "  $line" | tee -a "$OUT"
      record_finding "docker_exposed_all_interfaces" "$(echo "$line" | head -c 200)" "" '{"confidence":"maybe"}'
    done
fi

H "[CLEAR] services bound to 0.0.0.0 (potentially network-reachable)"
ss -tlnp 2>/dev/null | awk 'NR>1 && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\[::\]:/) {print}' | \
  while IFS= read -r line; do
    echo "  $line" | tee -a "$OUT"
    record_finding "listening_all_interfaces" "$(echo "$line" | head -c 200)" "" '{"confidence":"maybe"}'
  done

H "[CLEAR] PAM modules outside standard paths"
for m in $(find /tmp /var/tmp /dev/shm /opt /home -name 'pam_*.so' 2>/dev/null); do
  echo "  $m" | tee -a "$OUT"
  sha=$(sha256sum "$m" 2>/dev/null | awk '{print $1}')
  record_finding "pam_module_outside_standard_path" "$m" "$sha" '{"confidence":"clear"}'
done

echo | tee -a "$OUT"
echo "[hunt] CLEAR checks done; running MAYBE-backdoor / CyLG-specific checks..." | tee -a "$OUT"

H "[CLEAR] printer.exe / printer.* hunt (CyLG known backdoor)"
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  echo "$p" | tee -a "$OUT"
  sha=$(sha256sum "$p" 2>/dev/null | awk '{print $1}')
  record_finding "printer_exe_match" "$p" "$sha"
done < <(find / -name 'printer*' -type f 2>/dev/null | grep -vE '/proc|/sys|/snap|/var/cache')
R "ps auxf | grep -i printer | grep -v grep"
R "systemctl list-units --all 2>/dev/null | grep -i printer"
R "ls -la /etc/cron.* /etc/cron.d/ 2>/dev/null | grep -i printer"

H "Web shells (php/jsp/asp eval patterns) under /var/www and /srv"
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  echo "$f" | tee -a "$OUT"
  sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
  record_finding "webshell_pattern_match" "$f" "$sha"
done < <(grep -rEl 'eval *\(|system *\(|passthru *\(|base64_decode *\(|shell_exec *\(|assert *\(' /var/www /srv 2>/dev/null)

H "Recently modified system binaries (last 7 days)"
R "find /etc /usr/bin /usr/sbin /usr/local /lib /lib64 -mtime -7 -type f 2>/dev/null"

H "Deleted-binary processes (Meterpreter / in-memory loaders)"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "$line" | tee -a "$OUT"
  pid=$(echo "$line" | grep -oE '/proc/[0-9]+/exe' | head -1)
  record_finding "deleted_binary_process" "$pid" "" "{\"raw\":\"$(echo "$line" | sed 's/"/\\"/g' | head -c 150)\"}"
done < <(ls -la /proc/*/exe 2>/dev/null | grep deleted)

H "ld.so.preload (LD_PRELOAD rootkit)"
if [[ -s /etc/ld.so.preload ]]; then
  cat /etc/ld.so.preload | tee -a "$OUT"
  while IFS= read -r entry; do
    record_finding "ld_so_preload_entry" "$entry"
  done < /etc/ld.so.preload
else
  echo "(empty)" | tee -a "$OUT"
fi

H "PAM modules in non-standard locations"
R "find /lib/security /lib64/security /usr/lib/security 2>/dev/null -type f"
R "ls -la /etc/pam.d/"

H "SUID binaries not on common baseline"
R "common='/usr/bin/sudo|/usr/bin/passwd|/usr/bin/chsh|/usr/bin/gpasswd|/usr/bin/newgrp|/usr/bin/su|/usr/bin/mount|/usr/bin/umount|/usr/bin/chfn|/usr/bin/pkexec|/usr/lib/openssh/ssh-keysign|/usr/lib/dbus-1.0/dbus-daemon-launch-helper|/usr/lib/policykit-1/polkit-agent-helper-1|/usr/lib/snapd/snap-confine|/usr/bin/fusermount3|/usr/bin/fusermount|/usr/bin/at|/usr/bin/crontab|/usr/sbin/pppd|/usr/lib/eject/dmcrypt-get-device'; find / -perm -4000 -type f 2>/dev/null | grep -vE \"\$common\""

H "Hidden / executable files in tmp dirs"
R "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null"
R "find /tmp /var/tmp /dev/shm -name '.*' 2>/dev/null"

H "Cron jobs (all users) + cron drop dirs"
R 'for u in $(cut -d: -f1 /etc/passwd); do out=$(crontab -u "$u" -l 2>/dev/null); [ -n "$out" ] && echo "--- $u ---" && echo "$out"; done'
R "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null"

H "SSH authorized_keys (verify each)"
R 'for f in $(find /root/.ssh /home/*/.ssh -name authorized_keys 2>/dev/null); do echo "--- $f ---"; cat "$f"; done'

H "sshd_config: ForceCommand / Match blocks / AuthorizedKeysFile overrides"
R "grep -E '^(Match|ForceCommand|AuthorizedKeysFile|AuthorizedKeysCommand)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null"

H "/etc/passwd & /etc/shadow anomalies (UID 0 not root, empty pw)"
R 'awk -F: "\$3==0 {print}" /etc/passwd'
R 'awk -F: "\$2==\"\" {print \$1\" (empty pw)\"}" /etc/shadow 2>/dev/null'

H "Sysv init / rc.local / profile drops"
R "ls -la /etc/init.d/ 2>/dev/null"
R "cat /etc/rc.local 2>/dev/null"
R "ls -la /etc/profile.d/ 2>/dev/null"

H "Modified packages (debsums / rpm -Va)"
R "if command -v debsums >/dev/null; then debsums -c 2>/dev/null; elif command -v rpm >/dev/null; then rpm -Va 2>/dev/null; else echo '(neither installed — sudo apt install debsums)'; fi"

H "Listening sockets"
R "ss -tulpan 2>/dev/null || netstat -tulpan"

H "Established outbound connections"
R "ss -tan state established 2>/dev/null"

H "Unexpected systemd units (newer than /etc/hostname)"
R "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -newer /etc/hostname 2>/dev/null"

H "Diff against baselines (if present)"
for kind in suid modules listening services pkgs; do
  base="$OUTPUT_DIR/baseline-${kind}.txt"
  if [[ -f "$base" ]]; then
    case "$kind" in
      suid)      now=$(find / -perm -4000 -type f 2>/dev/null) ;;
      modules)   now=$(lsmod) ;;
      listening) now=$(ss -tulpan 2>/dev/null) ;;
      services)  now=$(systemctl list-unit-files --state=enabled 2>/dev/null) ;;
      pkgs)      now=$(dpkg -l 2>/dev/null) ;;
    esac
    diff_out=$(diff <(echo "$now") "$base" 2>/dev/null)
    if [[ -n "$diff_out" ]]; then
      echo "--- DIFF: $kind ---" | tee -a "$OUT"
      echo "$diff_out" | tee -a "$OUT"
    else
      echo "$kind: no drift" | tee -a "$OUT"
    fi
  fi
done

log "HUNT done -> $OUT"
info_box "Hunt complete:\n$OUT\n\nFor any hits — process from §A:\n1. DO NOT delete\n2. sha256sum + copy to evidence share\n3. Network-isolate the host\n4. Find ALL hosts with same hash\n5. Eradicate fleet-wide simultaneously\n6. Patch the entry point\n7. Log to #log + report to white cell"
