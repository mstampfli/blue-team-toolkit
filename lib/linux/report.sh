#!/usr/bin/env bash
# Security report card: roll facts.json + findings.jsonl up into a single graded
# report (A-F posture grade, prioritized issues, open findings) as HTML + Markdown.
# Reads what map/triage/hunt already wrote; runs nothing intrusive itself.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

FACTS="$OUTPUT_DIR/facts.json"
FINDINGS="$OUTPUT_DIR/findings.jsonl"
[[ -f "$FACTS" ]] || { whiptail --msgbox "No facts.json yet.\nRun option 2 (Map) first." 10 60; exit 0; }

fact()  { jq -r "$1 // \"\""    "$FACTS"; }
factn() { jq -r "$1 // 0"       "$FACTS"; }
factb() { jq -r "$1 // false"   "$FACTS"; }

crit=(); high=(); med=(); good=()

# --- posture signals (highest-signal subset of the recommend logic) ---
[[ "$(factn '.security_state.uid0_non_root_count')" -gt 0 ]] && crit+=("UID 0 account other than root present")
[[ "$(factn '.security_state.empty_password_users')" -gt 0 ]] && crit+=("Account with an empty password in /etc/shadow")
[[ "$(fact '.security_state.ld_so_preload')" == "present" ]] && crit+=("/etc/ld.so.preload is non-empty (possible LD_PRELOAD rootkit)")
[[ "$(fact '.exposure.iptables_input_policy')" == "ACCEPT" ]] && crit+=("iptables INPUT default policy is ACCEPT (no implicit deny)")

case "$(fact '.security_state.ssh_root_login')" in yes|default) high+=("SSH permits root login");; no) good+=("SSH root login disabled");; esac
case "$(fact '.security_state.ssh_password_auth')" in yes|default) high+=("SSH password authentication enabled");; no) good+=("SSH password auth disabled");; esac
[[ "$(factb '.security_state.auditd_running')" == "true" ]] && good+=("auditd active") || high+=("auditd not running")
[[ "$(fact '.security_state.ufw_state')" == "active" ]] && good+=("Host firewall (UFW) active") || high+=("Host firewall (UFW) not active")
exp=$(factn '.exposure.ports_bound_all_interfaces'); [[ "$exp" -gt 0 ]] && high+=("$exp service(s) bound to 0.0.0.0 (reachable on every attached network)")
svcr=$(factn '.exposure.service_principals_running_as_root'); [[ "$svcr" -gt 0 ]] && high+=("$svcr long-running service(s) running as root unnecessarily")

[[ "$(factb '.security_state.fail2ban_running')" == "true" ]] && good+=("fail2ban active") || med+=("fail2ban inactive")
[[ "$(factb '.security_state.apparmor_running')" == "true" ]] && good+=("AppArmor active") || med+=("AppArmor not running")
caps=$(factn '.exposure.capability_files_count'); [[ "$caps" -gt 0 ]] && med+=("$caps file(s) with non-standard CAP_* capabilities to audit")
ufwany=$(factn '.exposure.ufw_allow_anywhere_rules'); [[ "$ufwany" -gt 0 ]] && med+=("$ufwany firewall rule(s) allow from anywhere")

# --- findings.jsonl summary (leads accumulated by hunt/triage/map) ---
f_total=0; f_types=""
if [[ -f "$FINDINGS" ]]; then
  f_total=$(grep -c . "$FINDINGS" 2>/dev/null || echo 0)
  f_types=$(jq -r '.type' "$FINDINGS" 2>/dev/null | sort | uniq -c | sort -rn | head -12 | sed 's/^ *//')
fi

# --- grade ---
nc=${#crit[@]}; nh=${#high[@]}; nm=${#med[@]}
score=$(( nc*30 + nh*12 + nm*4 ))
(( f_total > 0 )) && score=$(( score + (f_total > 20 ? 20 : f_total) ))
if   (( score == 0 )); then grade="A"
elif (( score < 12 ));  then grade="B"
elif (( score < 30 ));  then grade="C"
elif (( score < 60 ));  then grade="D"
else grade="F"; fi
# an unresolved critical caps the grade at D
if (( nc > 0 )) && [[ "$grade" =~ ^[ABC]$ ]]; then grade="D"; fi

HOST="$(fact .host)"; [[ -z "$HOST" ]] && HOST="$(hostname)"
OSL="$(fact .os.distro) $(fact .os.version) (kernel $(fact .os.kernel))"
ROLES="$(jq -r '.role | to_entries[] | select(.value==true) | .key' "$FACTS" 2>/dev/null | paste -sd', ' -)"
[[ -z "$ROLES" ]] && ROLES="(none detected)"
GEN="$(date -u +%FT%TZ)"
HTML="$OUTPUT_DIR/report.html"
MD="$OUTPUT_DIR/report.md"

esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
gcolor() { case "$1" in A) echo "#2ecc71";; B) echo "#7fce4b";; C) echo "#f1c40f";; D) echo "#e67e22";; *) echo "#e74c3c";; esac; }

li_html() { local cls="$1"; shift; local -n arr=$1; (( ${#arr[@]} )) || { echo "<li class='none'>none</li>"; return; }; for x in "${arr[@]}"; do echo "<li class='$cls'>$(printf '%s' "$x" | esc)</li>"; done; }

# ---------- HTML ----------
{
cat <<HEAD
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report card: $HOST</title>
<style>
:root{--bg:#15110d;--card:#1d1812;--fg:#ece3d6;--mut:#a08f7a;--bd:#3a2f24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:32px}
.wrap{max-width:900px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}.mut{color:var(--mut)}
.grade{display:flex;align-items:center;gap:20px;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:20px;margin:18px 0}
.badge{width:84px;height:84px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:46px;font-weight:700;color:#15110d;background:$(gcolor "$grade")}
.score{font-size:13px;color:var(--mut)}h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin:24px 0 6px;border-bottom:1px solid var(--bd);padding-bottom:4px}
ul{margin:8px 0;padding-left:20px}li{margin:3px 0}li.crit{color:#ff8a80}li.high{color:#ffb74d}li.med{color:#fff3b0}li.good{color:#9be59b}li.none{color:var(--mut);list-style:none;margin-left:-12px}
table{border-collapse:collapse;width:100%;margin:8px 0}td{padding:3px 10px;border-bottom:1px solid var(--bd)}
.foot{color:var(--mut);font-size:12px;margin-top:28px;border-top:1px solid var(--bd);padding-top:10px}
</style></head><body><div class="wrap">
<h1>Security report card</h1>
<div class="mut">$(printf '%s' "$HOST" | esc) &middot; $(printf '%s' "$OSL" | esc)</div>
<div class="grade"><div class="badge">$grade</div><div>
<div>$nc critical &middot; $nh high &middot; $nm medium &middot; $f_total open findings</div>
<div class="score">posture score $score (lower is better) &middot; roles: $(printf '%s' "$ROLES" | esc)</div></div></div>
<h2>Critical, do now</h2><ul>$(li_html crit crit)</ul>
<h2>High, before exposure</h2><ul>$(li_html high high)</ul>
<h2>Medium, when time allows</h2><ul>$(li_html med med)</ul>
<h2>Already in good shape</h2><ul>$(li_html good good)</ul>
HEAD
echo "<h2>Open findings ($f_total) by type</h2><table>"
if [[ -n "$f_types" ]]; then echo "$f_types" | while read -r n t; do echo "<tr><td>$(printf '%s' "$t"|esc)</td><td class='mut'>$n</td></tr>"; done; else echo "<tr><td class='mut'>none recorded yet</td></tr>"; fi
echo "</table>"
cat <<FOOT
<div class="foot">Generated $GEN by Blue Team Toolkit from facts.json + findings.jsonl.
Run map (2), then hunt/triage (5/6), then regenerate for a fuller picture. Authorized defensive use only.</div>
</div></body></html>
FOOT
} > "$HTML"

# ---------- Markdown ----------
{
echo "# Security report card: $HOST"
echo
echo "**Grade $grade** ($nc critical, $nh high, $nm medium, $f_total open findings; posture score $score, lower is better)"
echo
echo "- Host: $HOST"
echo "- OS: $OSL"
echo "- Roles: $ROLES"
echo "- Generated: $GEN"
echo
emit() { local title="$1"; shift; local -n a=$1; echo "## $title"; if (( ${#a[@]} )); then printf -- '- %s\n' "${a[@]}"; else echo "- none"; fi; echo; }
emit "Critical, do now" crit
emit "High, before exposure" high
emit "Medium, when time allows" med
emit "Already in good shape" good
echo "## Open findings by type"
[[ -n "$f_types" ]] && echo "$f_types" | while read -r n t; do echo "- $t: $n"; done || echo "- none recorded yet"
echo
echo "_Generated by Blue Team Toolkit from facts.json + findings.jsonl. Authorized defensive use only._"
} > "$MD"

log "REPORT grade=$grade score=$score -> $HTML"
info_box "Security report card written:\n\nGrade: $grade  (score $score, lower is better)\n$nc critical, $nh high, $nm medium\n$f_total open findings\n\nHTML: $HTML\nMarkdown: $MD"
