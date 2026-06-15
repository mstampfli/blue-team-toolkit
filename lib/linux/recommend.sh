#!/usr/bin/env bash
# Read facts.json and emit a prioritized punch list.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

FACTS="$OUTPUT_DIR/facts.json"
[[ -f "$FACTS" ]] || { whiptail --msgbox "No facts.json yet.\nRun option 6 (Map) first." 10 60; exit 0; }

OUT="$OUTPUT_DIR/recommendations-$(date +%F-%H%M).txt"

# Helpers
fact() { jq -r "$1 // \"missing\"" "$FACTS"; }
factb() { jq -r "$1 // false" "$FACTS"; }    # boolean
factn() { jq -r "$1 // 0" "$FACTS"; }        # number
has_tool() { jq -r --arg t "$1" '.tools_present | index($t) // empty' "$FACTS"; }

p0=(); p1=(); p2=(); na=(); ok=(); tools_have=(); tools_miss=()

# ---- P0 / P1 / P2 logic ----
[[ "$(factn '.security_state.uid0_non_root_count')" -gt 0 ]] && p0+=("UID 0 user(s) other than root present, investigate IMMEDIATELY")
[[ "$(factn '.security_state.empty_password_users')" -gt 0 ]] && p0+=("Account(s) with EMPTY password in /etc/shadow, set or lock now")
[[ "$(fact '.security_state.ld_so_preload')" == "present" ]] && p0+=("/etc/ld.so.preload is non-empty, possible LD_PRELOAD rootkit (verify each entry)")

case "$(fact '.security_state.ssh_root_login')" in
  yes|default) p1+=("SSH PermitRootLogin is permissive, set to 'no' (harden step 1)") ;;
  no) ok+=("SSH root login disabled") ;;
esac
case "$(fact '.security_state.ssh_password_auth')" in
  yes|default) p1+=("SSH PasswordAuthentication = yes, set to 'no' once keys are deployed (harden step 2)") ;;
  no) ok+=("SSH password auth disabled") ;;
esac
[[ "$(factb '.security_state.auditd_running')" != "true" ]] && p1+=("auditd not running, install + load Neo23x0 ruleset (harden step 3)") || ok+=("auditd active")
[[ "$(factb '.security_state.fail2ban_running')" != "true" ]] && p1+=("fail2ban inactive (harden step 4)") || ok+=("fail2ban active")
[[ "$(fact '.security_state.ufw_state')" != "active" ]] && p1+=("UFW not active, enable default-deny inbound (harden step 5)") || ok+=("UFW active")
[[ "$(fact '.security_state.pkexec_setuid')" =~ ^[4-7][0-7]{3}$ ]] && p1+=("/usr/bin/pkexec still has setuid, apply PwnKit workaround (harden step 7)")

[[ "$(factb '.security_state.nf_tables_loaded')" == "true" ]] && p2+=("nf_tables loaded, if not in use, blacklist (CVE-2024-1086 risk reduction)")
[[ "$(factb '.security_state.apparmor_running')" != "true" ]] && p2+=("AppArmor not running, install + enable apparmor profiles")

# Role-driven priorities
[[ "$(factb '.role.samba')" == "true" ]] && {
  case "$(fact '.security_state.smb_min_protocol')" in
    SMB2|SMB3) ok+=("Samba min protocol >= SMB2") ;;
    *) p0+=("Samba running with default min protocol (SMB1 may be allowed), set 'min protocol = SMB2' in smb.conf") ;;
  esac
}
[[ "$(factb '.role.docker')" == "true" ]] && p2+=("Docker present, review for privileged containers + check for socket exposure (/var/run/docker.sock)")

# Exposure-driven (from facts.json)
exposed_count=$(factn '.exposure.ports_bound_all_interfaces')
[[ "$exposed_count" -gt 0 ]] && p1+=("$exposed_count service(s) bound to 0.0.0.0, reachable from any network they touch; review with 'ss -tlnp' and bind to specific interface or firewall off")
svc_root=$(factn '.exposure.service_principals_running_as_root')
[[ "$svc_root" -gt 0 ]] && p1+=("$svc_root long-running service(s) running as root that typically don't need to (nginx/apache/postgres/etc.), drop to dedicated user")
caps_count=$(factn '.exposure.capability_files_count')
[[ "$caps_count" -gt 0 ]] && p2+=("$caps_count file(s) with non-standard CAP_* capabilities, audit with: sudo getcap -r /")
ipt_pol=$(fact '.exposure.iptables_input_policy')
[[ "$ipt_pol" == "ACCEPT" ]] && p0+=("iptables INPUT default policy = ACCEPT (no implicit deny), set policy DROP and add explicit ACCEPT rules")
ufw_any=$(factn '.exposure.ufw_allow_anywhere_rules')
[[ "$ufw_any" -gt 0 ]] && p1+=("$ufw_any UFW rule(s) allow from ANYWHERE, review with 'sudo ufw status verbose'")
docker_exposed=$(factn '.exposure.docker_containers_exposed_to_all')
[[ "$docker_exposed" -gt 0 ]] && p1+=("$docker_exposed Docker container(s) publishing ports to 0.0.0.0, bind to 127.0.0.1 unless intended public")
[[ "$(factb '.role.nginx')" == "true" || "$(factb '.role.apache')" == "true" ]] && {
  p1+=("Web server running, run 'nuclei -t cves/' against this host + audit /var/www for webshell patterns")
  [[ -z "$(has_tool nuclei)" ]] && tools_miss+=("nuclei (template-based CVE scan against your web server)")
}
[[ "$(factb '.role.postgres')" == "true" || "$(factb '.role.mysql_or_mariadb')" == "true" ]] && p2+=("DB server present, check for default creds, listening interfaces, replication user perms")
[[ "$(factb '.role.bind')" == "true" ]] && p2+=("BIND DNS running, ensure recursion is restricted; disable zone transfers to unknown peers")
[[ "$(factb '.role.ad_realm_joined')" == "true" ]] && p1+=("Host AD-joined, ensure SSSD config + krb5.keytab perms locked down; add to BloodHound scope")

# Listening ports, flag risky exposures
RISKY_PORTS=$(jq -r '.listening_ports[] | select(. as $p | [21,23,135,139,445,3306,5432,5984,6379,9200,11211,27017] | index($p))' "$FACTS")
if [[ -n "$RISKY_PORTS" ]]; then
  ports_csv=$(echo "$RISKY_PORTS" | tr '\n' ',' | sed 's/,$//')
  p1+=("Risky ports listening: $ports_csv, confirm bound only to internal interfaces, segment from workstations")
fi

# ---- Lynis findings (if a report.dat exists) ----
lynis_index=""
lynis_warnings=()
lynis_suggestions=()
LYNIS_REPORT=""
for cand in /var/log/lynis-report.dat /var/log/lynis/lynis-report.dat; do
  if sudo test -r "$cand" 2>/dev/null; then LYNIS_REPORT="$cand"; break; fi
done
if [[ -n "$LYNIS_REPORT" ]]; then
  lynis_index=$(sudo grep -E '^hardening_index=' "$LYNIS_REPORT" 2>/dev/null | tail -1 | cut -d= -f2)
  while IFS= read -r line; do
    # warning[]=ID|TEXT|DETAIL|SOLUTION
    msg=$(echo "$line" | sed 's/^warning\[\]=//' | awk -F'|' '{printf "[%s] %s", $1, $2}')
    [[ -n "$msg" ]] && lynis_warnings+=("$msg")
  done < <(sudo grep -E '^warning\[\]=' "$LYNIS_REPORT" 2>/dev/null)
  while IFS= read -r line; do
    msg=$(echo "$line" | sed 's/^suggestion\[\]=//' | awk -F'|' '{printf "[%s] %s", $1, $2}')
    [[ -n "$msg" ]] && lynis_suggestions+=("$msg")
  done < <(sudo grep -E '^suggestion\[\]=' "$LYNIS_REPORT" 2>/dev/null)
fi

# ---- LinPEAS findings (most recent linpeas-*.txt) ----
linpeas_99=()
linpeas_critical=()
LINPEAS_FILE=$(ls -t "$OUTPUT_DIR"/linpeas-*.txt 2>/dev/null | head -1)
if [[ -n "$LINPEAS_FILE" ]]; then
  # 95%/99% confidence markers = known privesc vectors
  while IFS= read -r line; do linpeas_99+=("$line"); done < <(
    grep -aE '95%|99%' "$LINPEAS_FILE" 2>/dev/null \
      | sed -E 's/\x1b\[[0-9;]*m//g' \
      | head -20
  )
  # PE / kernel exploit suggestions (linpeas marks them with "POSSIBLE" or "[!]")
  while IFS= read -r line; do linpeas_critical+=("$line"); done < <(
    grep -aE '^\[!\]|POSSIBLE|EXPLOITABLE' "$LINPEAS_FILE" 2>/dev/null \
      | sed -E 's/\x1b\[[0-9;]*m//g' \
      | head -20
  )
fi

# ---- Tool availability ----
critical_tools=(velociraptor lynis nuclei nmap chainsaw loki yara linpeas auditd-rules-repo sigma)
for t in "${critical_tools[@]}"; do
  if [[ -n "$(has_tool "$t")" ]]; then
    tools_have+=("$t")
  else
    tools_miss+=("$t")
  fi
done

# ---- Render ----
{
  echo "============================================================"
  echo " HARDENING PUNCH LIST, $(fact .host)"
  echo " Generated: $(date)"
  echo "============================================================"
  echo
  echo "OS: $(fact .os.distro) $(fact .os.version) (kernel $(fact .os.kernel))"
  echo
  echo "Detected role:"
  jq -r '.role | to_entries[] | select(.value == true) | "  - " + .key' "$FACTS"
  echo

  if (( ${#p0[@]} )); then
    echo "*** P0, DO NOW *********************************************"
    printf '  [!] %s\n' "${p0[@]}"
    echo
  fi
  if (( ${#p1[@]} )); then
    echo "*** P1, Before exposure ******************************"
    printf '  [ ] %s\n' "${p1[@]}"
    echo
  fi
  if (( ${#p2[@]} )); then
    echo "*** P2, If time allows ************************************"
    printf '  [ ] %s\n' "${p2[@]}"
    echo
  fi
  if (( ${#ok[@]} )); then
    echo "+++ Already in good shape ++++++++++++++++++++++++++++++++++"
    printf '  [OK] %s\n' "${ok[@]}"
    echo
  fi

  if [[ -n "$LYNIS_REPORT" ]]; then
    echo "=== LYNIS FINDINGS ($LYNIS_REPORT) ==="
    [[ -n "$lynis_index" ]] && echo "  Hardening index: $lynis_index / 100"
    if (( ${#lynis_warnings[@]} )); then
      echo "  Warnings (P1):"
      printf '    [!] %s\n' "${lynis_warnings[@]}"
    fi
    if (( ${#lynis_suggestions[@]} )); then
      echo "  Suggestions (top 15, P2):"
      printf '    [ ] %s\n' "${lynis_suggestions[@]:0:15}"
      (( ${#lynis_suggestions[@]} > 15 )) && echo "    ... +$(( ${#lynis_suggestions[@]} - 15 )) more in $LYNIS_REPORT"
    fi
    echo
  fi

  if [[ -n "$LINPEAS_FILE" ]]; then
    echo "=== LINPEAS FINDINGS ($LINPEAS_FILE) ==="
    if (( ${#linpeas_critical[@]} )); then
      echo "  CRITICAL / known-exploitable (P0):"
      printf '    [!] %s\n' "${linpeas_critical[@]}"
    fi
    if (( ${#linpeas_99[@]} )); then
      echo "  95%/99% confidence findings (P1):"
      printf '    [ ] %s\n' "${linpeas_99[@]}"
    fi
    (( ${#linpeas_critical[@]} + ${#linpeas_99[@]} == 0 )) && echo "  (no high-confidence findings, review $LINPEAS_FILE manually)"
    echo
  fi

  echo "TOOLS PRESENT:"
  if (( ${#tools_have[@]} )); then printf '  ✔ %s\n' "${tools_have[@]}"; else echo '  (none of the critical set installed)'; fi
  echo
  echo "TOOLS MISSING (recommend installing via option 1):"
  if (( ${#tools_miss[@]} )); then printf '  ✗ %s\n' "${tools_miss[@]}"; else echo '  (all critical tools present, nice)'; fi
  echo
  echo "Listening (top): $(jq -c '.listening_ports' "$FACTS")"
  echo
  echo "Next: option 3 to walk the hardening checklist (dry-run by default)."
} | tee "$OUT"

log "RECOMMEND -> $OUT"
echo
read -rp "Press Enter to return to menu..."
