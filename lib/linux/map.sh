#!/usr/bin/env bash
# Discovery / map mode. Writes $OUTPUT_DIR/facts.json.
# Detects OS, role, listening services, security state, installed tools.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

FACTS="$OUTPUT_DIR/facts.json"
log "MAP start"

# OS identity
. /etc/os-release 2>/dev/null || true
DISTRO="${ID:-unknown}"
DISTRO_VER="${VERSION_ID:-unknown}"
KERNEL="$(uname -r)"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"

bool() { "$@" >/dev/null 2>&1 && echo true || echo false; }
svc_active() { systemctl is-active "$1" 2>/dev/null | grep -qx active && echo true || echo false; }

# Role detection
DOCKER=$(bool command -v docker)
LXC=$(bool command -v lxc)
NGINX=$(svc_active nginx)
APACHE=$([[ "$(svc_active apache2)" == "true" || "$(svc_active httpd)" == "true" ]] && echo true || echo false)
SAMBA=$(svc_active smbd)
BIND=$(svc_active bind9 || svc_active named)
POSTGRES=$(svc_active postgresql)
MYSQL=$([[ "$(svc_active mysql)" == "true" || "$(svc_active mariadb)" == "true" ]] && echo true || echo false)
REDIS=$(svc_active redis-server || svc_active redis)
SSSD=$(svc_active sssd)
REALM_JOINED=$(realm list 2>/dev/null | grep -q . && echo true || echo false)
DNS_RESOLVED=$(svc_active systemd-resolved)

# Security state
SMB_MIN_PROTO=$(testparm -s 2>/dev/null | grep -i 'min protocol' | awk -F'=' '{print $2}' | xargs || echo 'unset')
SSH_ROOT=$(grep -iE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
SSH_PWD=$(grep -iE '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
SSH_X11=$(grep -iE '^[[:space:]]*X11Forwarding' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
AUDITD=$(svc_active auditd)
FAIL2BAN=$(svc_active fail2ban)
APPARMOR=$(svc_active apparmor)
UFW_STATE=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo unknown)
PKEXEC_PERMS=$(stat -c '%a' /usr/bin/pkexec 2>/dev/null || echo absent)
LD_PRELOAD_FILE=$([[ -s /etc/ld.so.preload ]] && echo present || echo empty)
ROOT_UID0_OTHER=$(awk -F: '$3==0 && $1!="root"' /etc/passwd | wc -l)
EMPTY_PWD=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null | wc -l)
NF_TABLES_LOADED=$(lsmod 2>/dev/null | grep -E '^nf_tables' >/dev/null && echo true || echo false)

# Listening ports — port-only (legacy)
LISTEN_JSON=$(ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | head -30 \
  | jq -R . | jq -s .)
[[ -z "$LISTEN_JSON" || "$LISTEN_JSON" == "null" ]] && LISTEN_JSON='[]'

# Listening detailed — with bind interface + exposure level
# bind=0.0.0.0/* = any interface (potentially reachable from network)
# bind=127.x.x.x/[::1] = localhost only
# bind=10.x.x.x = specific interface (private LAN)
LISTEN_DETAILED=$(
  ss -Hltn 2>/dev/null | awk '
    {
      addr = $4
      n = split(addr, a, ":")
      port = a[n]
      bind = addr
      sub(":[0-9]+$", "", bind)
      gsub(/[\[\]]/, "", bind)
      if (bind == "0.0.0.0" || bind == "*" || bind == "::") expo = "all_interfaces"
      else if (bind ~ /^127\./ || bind == "::1")            expo = "localhost_only"
      else                                                   expo = "specific_interface"
      printf "{\"port\":%s,\"bind\":\"%s\",\"exposure\":\"%s\"}\n", port, bind, expo
    }
  ' | jq -s '. | unique_by(.port + .bind)'
)
[[ -z "$LISTEN_DETAILED" || "$LISTEN_DETAILED" == "null" ]] && LISTEN_DETAILED='[]'

# Anything bound to 0.0.0.0 is potentially exposed externally (depends on firewall)
EXPOSED_PORT_COUNT=$(echo "$LISTEN_DETAILED" | jq '[.[] | select(.exposure == "all_interfaces")] | length')

# Capability files (CAP_*) — non-empty means binaries can do privileged things without setuid
CAPS_COUNT=$(sudo getcap -r / 2>/dev/null | grep -vE '^$|/(ping|arping|traceroute|tracepath|fping)$|/usr/bin/(ping|arping|traceroute|tracepath|fping)' | wc -l)

# Service principals running as root
SVCS_AS_ROOT_RISKY=$(ps -eo user,comm --no-headers 2>/dev/null | \
  awk '$1=="root" && $2 ~ /^(nginx|apache2|httpd|mysqld|mariadbd|postgres|redis-server|mongod|node|php-fpm|tomcat|java|python)$/' | wc -l)

# Firewall posture
IPT_INPUT_POLICY=$(sudo iptables -L INPUT 2>/dev/null | head -1 | grep -oE 'policy [A-Z]+' | awk '{print $2}')
UFW_RULES_ANY=$(sudo ufw status 2>/dev/null | grep -cE 'ALLOW.*Anywhere')
DOCKER_EXPOSED=0
if command -v docker >/dev/null 2>&1; then
  DOCKER_EXPOSED=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -cE '0\.0\.0\.0:|::')
fi

# Installed/downloaded tools
TOOLS=()
# 1) Tools that land on PATH via apt/pip
for t in nmap masscan lynis yara chkrootkit rkhunter unhide auditd fail2ban suricata zeek tcpdump wireshark gobuster nikto enum4linux-ng debsums volatility3 nxc nuclei chainsaw hayabusa velociraptor; do
  command -v "$t" >/dev/null 2>&1 && TOOLS+=("$t")
done
# 2) Tools downloaded into $TOOLS_DIR (binaries / archives / single scripts / git clones)
have_glob() { compgen -G "$1" >/dev/null 2>&1; }

have_glob "$TOOLS_DIR/velociraptor*linux*"            && TOOLS+=("velociraptor")
have_glob "$TOOLS_DIR/nuclei*linux*"                  && TOOLS+=("nuclei")
have_glob "$TOOLS_DIR/chainsaw*linux*"                && TOOLS+=("chainsaw")
have_glob "$TOOLS_DIR/hayabusa*linux*"                && TOOLS+=("hayabusa")
have_glob "$TOOLS_DIR/loki_*"                         && TOOLS+=("loki")
have_glob "$TOOLS_DIR/avml"                           && TOOLS+=("avml")
[[ -f "$TOOLS_DIR/linpeas.sh" ]]                      && TOOLS+=("linpeas")
[[ -f "$TOOLS_DIR/linux-exploit-suggester.sh" ]]      && TOOLS+=("linux-exploit-suggester")
[[ -d "$TOOLS_DIR/sysmon-config" ]]                   && TOOLS+=("sysmon-config")
[[ -d "$TOOLS_DIR/sysmon-modular" ]]                  && TOOLS+=("sysmon-modular")
[[ -d "$TOOLS_DIR/auditd-rules" ]]                    && TOOLS+=("auditd-rules-repo")
[[ -d "$TOOLS_DIR/sigma" ]]                           && TOOLS+=("sigma")
[[ -d "$TOOLS_DIR/cowrie" ]]                          && TOOLS+=("cowrie")

TOOLS_JSON=$(printf '%s\n' "${TOOLS[@]}" | jq -R . | jq -s 'unique')

jq -n \
  --arg host       "$HOSTNAME_FQDN" \
  --arg distro     "$DISTRO" \
  --arg distrover  "$DISTRO_VER" \
  --arg kernel     "$KERNEL" \
  --argjson docker $DOCKER \
  --argjson lxc    $LXC \
  --argjson nginx  $NGINX \
  --argjson apache $APACHE \
  --argjson samba  $SAMBA \
  --argjson bind   $BIND \
  --argjson pg     $POSTGRES \
  --argjson mysql  $MYSQL \
  --argjson redis  $REDIS \
  --argjson sssd   $SSSD \
  --argjson realm  $REALM_JOINED \
  --argjson resolved $DNS_RESOLVED \
  --arg smb_min    "${SMB_MIN_PROTO:-unset}" \
  --arg ssh_root   "${SSH_ROOT:-default}" \
  --arg ssh_pwd    "${SSH_PWD:-default}" \
  --arg ssh_x11    "${SSH_X11:-default}" \
  --argjson auditd $AUDITD \
  --argjson f2b    $FAIL2BAN \
  --argjson aa     $APPARMOR \
  --arg ufw        "${UFW_STATE:-unknown}" \
  --arg pkexec     "$PKEXEC_PERMS" \
  --arg ldpreload  "$LD_PRELOAD_FILE" \
  --argjson uid0   "$ROOT_UID0_OTHER" \
  --argjson emptyp "$EMPTY_PWD" \
  --argjson nft    "$NF_TABLES_LOADED" \
  --argjson listen "$LISTEN_JSON" \
  --argjson listen_detailed "$LISTEN_DETAILED" \
  --argjson exposed_count "$EXPOSED_PORT_COUNT" \
  --argjson caps_count "$CAPS_COUNT" \
  --argjson svc_root "$SVCS_AS_ROOT_RISKY" \
  --arg ipt_pol "${IPT_INPUT_POLICY:-unknown}" \
  --argjson ufw_any "$UFW_RULES_ANY" \
  --argjson docker_exposed "$DOCKER_EXPOSED" \
  --argjson tools  "$TOOLS_JSON" \
  '{
    host: $host,
    platform: "linux",
    scanned_at: (now | todate),
    os: { distro: $distro, version: $distrover, kernel: $kernel },
    role: {
      docker: $docker, lxc: $lxc,
      nginx: $nginx, apache: $apache, samba: $samba, bind: $bind,
      postgres: $pg, mysql_or_mariadb: $mysql, redis: $redis,
      sssd: $sssd, ad_realm_joined: $realm, systemd_resolved: $resolved
    },
    security_state: {
      smb_min_protocol: $smb_min,
      ssh_root_login: $ssh_root,
      ssh_password_auth: $ssh_pwd,
      ssh_x11_forwarding: $ssh_x11,
      auditd_running: $auditd,
      fail2ban_running: $f2b,
      apparmor_running: $aa,
      ufw_state: $ufw,
      pkexec_setuid: $pkexec,
      ld_so_preload: $ldpreload,
      uid0_non_root_count: $uid0,
      empty_password_users: $emptyp,
      nf_tables_loaded: $nft
    },
    listening_ports: $listen,
    listening_detailed: $listen_detailed,
    exposure: {
      ports_bound_all_interfaces: $exposed_count,
      capability_files_count: $caps_count,
      service_principals_running_as_root: $svc_root,
      iptables_input_policy: $ipt_pol,
      ufw_allow_anywhere_rules: $ufw_any,
      docker_containers_exposed_to_all: $docker_exposed
    },
    tools_present: $tools
  }' > "$FACTS"

log "MAP wrote $FACTS"

# --- Single upfront checklist for heavy passes (no per-tool prompts) ---
opts=()
command -v lynis >/dev/null 2>&1     && opts+=("lynis"   "lynis audit (5-10 min, read-only)"     "OFF")
command -v nmap  >/dev/null 2>&1     && opts+=("nmap"    "nmap top-1000 vs 127.0.0.1 (10-30s)"   "ON")
[[ -f "$TOOLS_DIR/linpeas.sh" ]]     && opts+=("linpeas" "linpeas.sh (3-5 min)"                  "OFF")

heavy=""
if (( ${#opts[@]} )); then
  clear
  heavy=$(whiptail --title "Heavy passes" \
    --checklist "Pick which heavy tools to run after map (Space to toggle, Enter to confirm).\nAll output goes to files in output/ — your terminal stays clean." \
    20 80 6 "${opts[@]}" 3>&1 1>&2 2>&3) || heavy=""
fi

# run_silent now lives in common.sh

for tool in $heavy; do
  tool="${tool//\"/}"
  clear
  case "$tool" in
    lynis)   run_silent "lynis"   "$OUTPUT_DIR/lynis-$(date +%F-%H%M).log"   sudo lynis audit system --quick --no-colors ;;
    nmap)    run_silent "nmap"    "$OUTPUT_DIR/nmap-localhost-$(date +%F-%H%M).log" nmap -sV -sC -T4 --top-ports 1000 -oA "$OUTPUT_DIR/nmap-localhost-$(date +%F-%H%M)" 127.0.0.1 ;;
    linpeas) run_silent "linpeas" "$OUTPUT_DIR/linpeas-$(date +%F-%H%M).txt" bash "$TOOLS_DIR/linpeas.sh" -a ;;
  esac
done

# Record map-detected anomalies as persistent findings
[[ "$ROOT_UID0_OTHER" -gt 0 ]] && record_finding "uid0_non_root_account" "/etc/passwd" "" "{\"count\":$ROOT_UID0_OTHER}"
[[ "$EMPTY_PWD" -gt 0 ]]       && record_finding "empty_password_user"  "/etc/shadow" "" "{\"count\":$EMPTY_PWD}"
[[ "$LD_PRELOAD_FILE" == "present" ]] && record_finding "ld_so_preload_present" "/etc/ld.so.preload"

clear
info_box "Map complete.\n\nfacts.json: $FACTS\nLogs: $OUTPUT_DIR\n\nNext: option 7 (Recommendations) for the punch list."
