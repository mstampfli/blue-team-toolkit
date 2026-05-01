#!/usr/bin/env bash
# Network recon — INTERNAL sweep + EXTERNAL exposure check.
# Internal: nmap live discovery + service detect, NetExec SMB, whatweb on web ports.
# External: Shodan InternetDB (no API key needed), NAT-hairpin nmap, DNS + crt.sh.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

TARGETS_FILE="$OUTPUT_DIR/recon-targets.txt"
THOROUGH=0
INTERNET_OK=0

# --- thoroughness selector + internet test ---

choose_thoroughness() {
  local c
  c=$(whiptail --title "Scan depth" --menu \
    "Pick depth (per /24 estimate):" 16 80 3 \
    "QUICK" "Top-1000 ports + default scripts (~5-15 min)" \
    "FULL"  "All 65k ports + vuln scripts + nuclei + openvas (~1-4 HOURS)" \
    "BACK"  "Cancel" \
    3>&1 1>&2 2>&3) || return 1
  case "$c" in
    QUICK) THOROUGH=0 ;;
    FULL)  THOROUGH=1 ;;
    BACK)  return 1 ;;
  esac
  return 0
}

check_internet() {
  if curl -fsSL --max-time 5 https://1.1.1.1 >/dev/null 2>&1 \
     || curl -fsSL --max-time 5 http://example.com >/dev/null 2>&1; then
    INTERNET_OK=1
  else
    INTERNET_OK=0
  fi
}

nmap_service_args() {
  if [[ "$THOROUGH" == "1" ]]; then
    echo "-sV -sC -A -p- --script default,vuln,vulners -T4 --version-intensity 9 --max-retries 2"
  else
    echo "-sV -sC -T4 --top-ports 1000"
  fi
}

nmap_disco_args() {
  # Live discovery — same in both modes (fast)
  echo "-sn -T4 -PE -PP -PS21,22,23,25,80,113,443,445,3389 -PA80,443,3389"
}

# --- target list management ---

init_targets() {
  [[ -f "$TARGETS_FILE" ]] && return
  rebuild_targets
}

rebuild_targets() {
  {
    echo "# Recon targets — auto-detected $(date +'%F %T'). Edit before running if needed."
    echo "# Format: <type> <value>  [# comment]"
    echo "# type = internal_cidr | external_ip | external_domain"
    echo
    ip -o -f inet route 2>/dev/null \
      | awk '/proto kernel/ && $1 !~ /^(127\.|169\.254\.)/ {print $1}' \
      | sort -u | while read -r cidr; do
          echo "internal_cidr $cidr  # auto-detected from ip route"
        done
    echo
    pubip=$(curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
            || curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
            || curl -fsSL --max-time 5 https://icanhazip.com 2>/dev/null)
    [[ -n "$pubip" ]] && echo "external_ip $pubip  # auto-detected"
    # Try resolving local hostname back to a domain
    fqdn=$(hostname -f 2>/dev/null)
    if [[ "$fqdn" == *.* && "$fqdn" != *localdomain* ]]; then
      domain="${fqdn#*.}"
      echo "external_domain $domain  # auto-detected from hostname -f"
    else
      echo "# external_domain example.com    # add manually if you have a public domain"
    fi
  } > "$TARGETS_FILE"
}

auto_recon() {
  # Re-detect everything fresh, then run internal on each + external, no prompts.
  echo "[recon] AUTO mode — re-detecting targets..."
  rebuild_targets
  cat "$TARGETS_FILE" | grep -vE '^\s*#|^\s*$'
  echo
  echo "[recon] sleeping 3s — Ctrl-C to abort"
  sleep 3
  internal_recon
  external_recon
  clear
  echo "[recon] AUTO complete."
  echo "  facts updated, findings appended to $OUTPUT_DIR/findings.jsonl"
  echo "  see option 7 (Recommendations) for the punch list"
  read -rp "Press Enter to continue..."
}

edit_targets() {
  ${EDITOR:-nano} "$TARGETS_FILE"
}

show_targets() {
  clear
  echo "=== $TARGETS_FILE ==="
  grep -vE '^\s*#|^\s*$' "$TARGETS_FILE"
  echo
  read -rp "Press Enter to continue..."
}

get_targets() {
  local type="$1"
  grep -E "^$type" "$TARGETS_FILE" 2>/dev/null | awk '{print $2}'
}

# --- nmap output parsing into findings ---

parse_nmap_findings() {
  local nmap_file="$1" context="$2"
  local current_host=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^Nmap\ scan\ report\ for\ (.+)$ ]]; then
      current_host="${BASH_REMATCH[1]}"
      current_host="${current_host%% *}"
    elif [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+([^[:space:]]+)(.*)$ ]]; then
      local port="${BASH_REMATCH[1]}"
      local proto="${BASH_REMATCH[2]}"
      local svc="${BASH_REMATCH[3]}"
      local banner=$(echo "${BASH_REMATCH[4]}" | sed 's/^[[:space:]]*//' | head -c 100 | sed 's/"/\\"/g')
      record_finding "${context}_open_port" "$current_host:$port/$proto" "" \
        "{\"service\":\"$svc\",\"banner\":\"$banner\",\"confidence\":\"$( [[ $context == external* ]] && echo clear || echo informational )\"}"
    fi
  done < "$nmap_file"
}

# --- INTERNAL ---

internal_recon() {
  local cidrs
  cidrs=$(get_targets internal_cidr)
  if [[ -z "$cidrs" ]]; then
    info_box "No 'internal_cidr' lines in $TARGETS_FILE.\nUse menu option TARGETS first."
    return
  fi

  local stamp
  stamp=$(date +%F-%H%M)
  local livefile="$OUTPUT_DIR/recon-internal-live-$stamp.txt"
  : > "$livefile"

  # 1) Live host discovery (nmap -sn) per CIDR — fast even in thorough mode
  local disco_args; disco_args=$(nmap_disco_args)
  for cidr in $cidrs; do
    local clean="${cidr//\//_}"
    local LH="$OUTPUT_DIR/recon-internal-livehosts-${clean}-$stamp.log"
    clear
    run_silent "nmap-sn $cidr" "$LH" sudo nmap $disco_args -oG - "$cidr"
    grep "Status: Up" "$LH" 2>/dev/null | awk '{print $2}' >> "$livefile"
  done

  local nlive
  nlive=$(wc -l < "$livefile")
  echo
  echo "[recon] $nlive live hosts found across $(echo $cidrs | wc -w) CIDR(s) -> $livefile"
  log "Internal recon: $nlive live hosts"

  if [[ "$nlive" -eq 0 ]]; then
    info_box "No live hosts found. Check the CIDRs in $TARGETS_FILE and your routing."
    return
  fi

  # 2) Service detect against live hosts only
  local SVC="$OUTPUT_DIR/recon-internal-services-$stamp"
  local svc_args; svc_args=$(nmap_service_args)
  local desc; desc=$([[ "$THOROUGH" == "1" ]] && echo "FULL: -p- + vuln scripts + vulners" || echo "QUICK: top-1000 + default scripts")
  clear
  run_silent "nmap $desc (×$nlive hosts)" "$SVC.log" \
    sudo nmap $svc_args -iL "$livefile" -oA "$SVC"
  parse_nmap_findings "$SVC.nmap" "internal"

  # Parse vulners script output (when THOROUGH) — these are CLEAR CVE matches
  if [[ "$THOROUGH" == "1" ]]; then
    grep -E '\| *(CVE-[0-9]+-[0-9]+|VULNERABLE)' "$SVC.nmap" 2>/dev/null | while IFS= read -r line; do
      cve=$(echo "$line" | grep -oE 'CVE-[0-9]{4}-[0-9]+' | head -1)
      record_finding "nmap_vulners_cve" "$(echo "$line" | head -c 200)" "" "{\"cve\":\"${cve:-unknown}\",\"confidence\":\"clear\"}"
    done
  fi

  # 3) SMB enum on hosts with 445 open
  if command -v nxc >/dev/null 2>&1; then
    grep -B5 '445/tcp.*open' "$SVC.nmap" 2>/dev/null \
      | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()' \
      | sort -u > "$OUTPUT_DIR/.smb-hosts.tmp"
    if [[ -s "$OUTPUT_DIR/.smb-hosts.tmp" ]]; then
      local SMB="$OUTPUT_DIR/recon-internal-smb-$stamp.log"
      clear
      run_silent "nxc smb --shares" "$SMB" \
        bash -c "nxc smb \$(cat '$OUTPUT_DIR/.smb-hosts.tmp' | tr '\n' ' ') --shares 2>&1; \
                 nxc smb \$(cat '$OUTPUT_DIR/.smb-hosts.tmp' | tr '\n' ' ') --pass-pol 2>&1"
      grep -E 'READ.*ALL|Anonymous|signing:False' "$SMB" 2>/dev/null | while IFS= read -r line; do
        record_finding "smb_weak_config" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
      done
    fi
    rm -f "$OUTPUT_DIR/.smb-hosts.tmp"
  fi

  # 4) Web fingerprint on web ports + nikto + nuclei
  local web_hosts="$OUTPUT_DIR/.web-hosts.tmp"
  grep -B5 -E '(80|443|8080|8443|8000|8888|9000|9090|9443)/tcp.*open' "$SVC.nmap" 2>/dev/null \
    | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()' \
    | sort -u > "$web_hosts"

  if [[ -s "$web_hosts" ]]; then
    if command -v whatweb >/dev/null 2>&1; then
      local WW="$OUTPUT_DIR/recon-internal-whatweb-$stamp.log"
      clear
      run_silent "whatweb -a 3" "$WW" \
        bash -c "whatweb -a 3 \$(cat '$web_hosts' | tr '\n' ' ')"
    fi

    if [[ "$THOROUGH" == "1" ]] && command -v nikto >/dev/null 2>&1; then
      local NK="$OUTPUT_DIR/recon-internal-nikto-$stamp.log"
      clear
      run_silent "nikto vs $(wc -l < "$web_hosts") web hosts" "$NK" \
        bash -c "while read h; do nikto -h \"\$h\" -nointeractive 2>&1; done < '$web_hosts'"
      grep -E '^\+ OSVDB-|CVE-' "$NK" 2>/dev/null | while IFS= read -r line; do
        record_finding "nikto_finding" "$(echo "$line" | head -c 200)" "" '{"confidence":"clear"}'
      done
    fi

    # nuclei — runs in both modes; severity threshold differs
    local NUCLEI_BIN
    NUCLEI_BIN=$(ensure_extracted "nuclei*linux*.zip" "nuclei")
    if [[ -n "$NUCLEI_BIN" ]]; then
      local nuclei_urls="$OUTPUT_DIR/.nuclei-urls.tmp"
      : > "$nuclei_urls"
      while read -r h; do
        echo "http://$h"  >> "$nuclei_urls"
        echo "https://$h" >> "$nuclei_urls"
      done < "$web_hosts"
      local NU="$OUTPUT_DIR/recon-internal-nuclei-$stamp.log"
      local sevs="critical,high"
      [[ "$THOROUGH" == "1" ]] && sevs="critical,high,medium,low"
      clear
      run_silent "nuclei vs $(wc -l < "$nuclei_urls") URLs (sev=$sevs)" "$NU" \
        "$NUCLEI_BIN" -l "$nuclei_urls" -severity "$sevs" -nc -silent
      while IFS= read -r line; do
        cve=$(echo "$line" | grep -oE 'CVE-[0-9]{4}-[0-9]+' | head -1)
        sev=$(echo "$line" | grep -oE '\[(critical|high|medium|low)\]' | head -1 | tr -d '[]')
        target=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
        [[ -n "$target" ]] && record_finding "nuclei_cve" "$target" "" \
          "{\"cve\":\"${cve:-unknown}\",\"severity\":\"${sev:-unknown}\",\"confidence\":\"clear\"}"
      done < "$NU"
      rm -f "$nuclei_urls"
    fi
  fi
  rm -f "$web_hosts"

  # 5) OpenVAS — only in THOROUGH mode if running
  if [[ "$THOROUGH" == "1" ]]; then
    openvas_dispatch "$cidrs" "$stamp"
  fi

  clear
  echo "[recon] internal sweep complete."
  echo "  live hosts : $livefile  ($nlive hosts)"
  echo "  services   : $SVC.{nmap,gnmap,xml}"
  echo "  findings recorded to: $OUTPUT_DIR/findings.jsonl"
  read -rp "Press Enter to continue..."
}

# --- OpenVAS / GVM dispatch ---

openvas_dispatch() {
  local cidrs="$1" stamp="$2"
  clear
  echo "[recon] OpenVAS / GVM check..."
  if ! command -v gvm-cli >/dev/null 2>&1 && ! command -v gvm-start >/dev/null 2>&1; then
    cat <<EOF
OpenVAS / GVM not installed.

To set up (one-time, 30-60 min interactive):
  sudo apt install -y gvm
  sudo gvm-setup        # downloads feeds, creates admin user, prints password
  sudo gvm-start        # launches gsad + ospd-openvas + gvmd

Once running, web UI: https://localhost:9392
Or skip web UI and re-run this thorough scan — toolkit will drive gvm-cli.
EOF
    read -rp "Press Enter to continue..."
    return
  fi

  if ! pgrep -f gsad >/dev/null && ! systemctl is-active --quiet gsad 2>/dev/null; then
    echo "GVM installed but daemon not running. Start with: sudo gvm-start"
    read -rp "Press Enter to continue..."
    return
  fi

  if ! command -v gvm-cli >/dev/null 2>&1; then
    echo "gvm-cli missing. Install: sudo apt install -y python3-gvm gvm-tools"
    read -rp "Press Enter to continue..."
    return
  fi

  echo "GVM is running. Toolkit will create a target + task and start a scan."
  read -rp "GVM admin user [admin]: " gvm_user; gvm_user="${gvm_user:-admin}"
  read -rsp "GVM admin password: " gvm_pass; echo
  [[ -z "$gvm_pass" ]] && { echo "No password — skipping OpenVAS."; read -rp "Press Enter..."; return; }

  local target_hosts
  target_hosts=$(echo "$cidrs" | tr '\n' ',' | sed 's/,$//')
  local target_name="bt-toolkit-${stamp}"

  # Get Full and Fast scan config ID (standard built-in)
  local config_id="daba56c8-73ec-11df-a475-002264764cea"
  # Default OpenVAS Default scanner
  local scanner_id="08b69003-5fc2-4037-a479-93b440211c73"

  echo "[recon] Creating target $target_name -> $target_hosts"
  local target_xml="<create_target><name>$target_name</name><hosts>$target_hosts</hosts></create_target>"
  local target_id
  target_id=$(gvm-cli --gmp-username "$gvm_user" --gmp-password "$gvm_pass" \
                 socket --xml "$target_xml" 2>/dev/null \
                 | grep -oE 'id="[^"]+"' | head -1 | cut -d'"' -f2)
  if [[ -z "$target_id" ]]; then
    echo "Failed to create target. Check creds + that ospd-openvas is up."
    read -rp "Press Enter..."; return
  fi

  echo "[recon] Creating task..."
  local task_xml="<create_task><name>$target_name</name><config id=\"$config_id\"/><target id=\"$target_id\"/><scanner id=\"$scanner_id\"/></create_task>"
  local task_id
  task_id=$(gvm-cli --gmp-username "$gvm_user" --gmp-password "$gvm_pass" \
              socket --xml "$task_xml" 2>/dev/null \
              | grep -oE 'id="[^"]+"' | head -1 | cut -d'"' -f2)
  [[ -z "$task_id" ]] && { echo "Failed to create task."; read -rp "Press Enter..."; return; }

  echo "[recon] Starting task $task_id..."
  gvm-cli --gmp-username "$gvm_user" --gmp-password "$gvm_pass" \
    socket --xml "<start_task task_id=\"$task_id\"/>" >/dev/null 2>&1
  log "OpenVAS task $task_id started against $target_hosts"

  cat <<EOF

OpenVAS scan kicked off.
  task_id : $task_id
  target  : $target_hosts
  user    : $gvm_user

Monitor in web UI: https://localhost:9392/  (Scans -> Tasks)

When done, export the report:
  gvm-cli --gmp-username '$gvm_user' --gmp-password '<pw>' socket \\
    --xml '<get_reports task_id="$task_id" report_format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>' \\
    > $OUTPUT_DIR/openvas-report-$stamp.xml

Toolkit doesn't poll/wait — task may run for hours. Re-check via web UI.
EOF
  record_finding "openvas_scan_started" "$target_hosts" "" "{\"task_id\":\"$task_id\",\"confidence\":\"informational\"}"
  read -rp "Press Enter to continue..."
}

# --- EXTERNAL ---

external_recon() {
  local ips domains stamp
  ips=$(get_targets external_ip)
  domains=$(get_targets external_domain)
  stamp=$(date +%F-%H%M)

  if [[ -z "$ips" && -z "$domains" ]]; then
    info_box "No external_ip or external_domain in $TARGETS_FILE.\nUse menu option TARGETS first."
    return
  fi

  if [[ "$INTERNET_OK" != "1" ]]; then
    cat <<EOF
[recon] No internet detected.

In an air-gapped exercise, "external" view means scanning your assets from a
DIFFERENT VLAN (your DMZ side, your "user" VLAN, etc). Add those CIDRs as
'internal_cidr' lines in $TARGETS_FILE and run INTERNAL — that gives you the
"what does the other side see" picture for each VLAN you control.

Skipping Shodan + crt.sh (both require internet). Running NAT-hairpin nmap
and local DNS dig only.
EOF
    read -rp "Press Enter to continue..."
  fi

  # 1) Shodan InternetDB — passive, free, no API key (only if internet)
  if [[ -n "$ips" && "$INTERNET_OK" == "1" ]]; then
    local SH="$OUTPUT_DIR/recon-external-shodan-$stamp.json"
    : > "$SH"
    clear
    echo "[recon] Querying Shodan InternetDB (passive, no API key)..."
    for ip in $ips; do
      echo "  -> $ip"
      result=$(curl -fsSL --max-time 10 -H 'User-Agent: blueteam-toolkit' "https://internetdb.shodan.io/$ip" 2>/dev/null)
      if [[ -n "$result" && "$result" != *"No information"* ]]; then
        echo "$result" | jq --arg ip "$ip" '. + {queried_ip: $ip}' >> "$SH"
        echo "$result" | jq -r '.ports[]?'  | while read -r p; do
          [[ -n "$p" ]] && record_finding "exposed_external_port" "$ip:$p" "" '{"source":"shodan_internetdb","confidence":"clear"}'
        done
        echo "$result" | jq -r '.vulns[]?' | while read -r v; do
          [[ -n "$v" ]] && record_finding "external_known_vuln" "$ip" "" "{\"cve\":\"$v\",\"source\":\"shodan_internetdb\",\"confidence\":\"clear\"}"
        done
        echo "$result" | jq -r '.tags[]?' | while read -r t; do
          [[ -n "$t" ]] && record_finding "external_service_tag" "$ip" "" "{\"tag\":\"$t\",\"source\":\"shodan_internetdb\"}"
        done
        echo "    ports: $(echo "$result" | jq -c '.ports')"
        echo "    vulns: $(echo "$result" | jq -c '.vulns')"
        echo "    tags : $(echo "$result" | jq -c '.tags')"
      else
        echo "    (not in Shodan dataset)"
      fi
    done
    log "Shodan InternetDB results -> $SH"
    read -rp "Press Enter to continue..."
  fi

  # 2) NAT-hairpin nmap — runs always; toolkit prints the caveat at end
  if [[ -n "$ips" ]]; then
    for ip in $ips; do
      local clean="${ip//./_}"
      local NM="$OUTPUT_DIR/recon-external-nmap-${clean}-$stamp"
      clear
      run_silent "nmap external $ip" "$NM.log" \
        sudo nmap -sV --top-ports 1000 -T4 -Pn -oA "$NM" "$ip"
      parse_nmap_findings "$NM.nmap" "external_via_lan"
    done
  fi

  # 3) DNS enum + crt.sh subdomain enum (crt.sh needs internet, dig works locally)
  if [[ -n "$domains" ]]; then
    for domain in $domains; do
      local DNS="$OUTPUT_DIR/recon-external-dns-${domain}-$stamp.log"
      clear
      echo "[recon] DNS enumeration for $domain"
      {
        echo "=== A records ==="          ; dig +short "$domain" A
        echo "=== AAAA records ==="       ; dig +short "$domain" AAAA
        echo "=== MX records ==="         ; dig +short "$domain" MX
        echo "=== NS records ==="         ; dig +short "$domain" NS
        echo "=== TXT records ==="        ; dig +short "$domain" TXT
        echo "=== SPF (in TXT) ==="       ; dig +short "$domain" TXT | grep -i spf
        echo "=== DMARC ==="              ; dig +short "_dmarc.$domain" TXT
        echo "=== CAA records ==="        ; dig +short "$domain" CAA
        if [[ "$INTERNET_OK" == "1" ]]; then
          echo
          echo "=== Subdomains via crt.sh ==="
          curl -fsSL --max-time 30 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
            | jq -r '.[].name_value' 2>/dev/null \
            | tr ',' '\n' | sort -u | grep -v '^\*'
        else
          echo
          echo "=== crt.sh skipped (no internet) ==="
        fi
      } | tee "$DNS"
      log "DNS enum $domain -> $DNS"

      grep -oE "[a-z0-9.-]+\\.${domain//./\\.}" "$DNS" 2>/dev/null | sort -u | while read -r sub; do
        [[ -n "$sub" ]] && record_finding "external_subdomain" "$sub"
      done

      # 4) subfinder if installed (passive sources)
      SUBFINDER=$(ensure_extracted "subfinder*linux*.zip" "subfinder" 2>/dev/null)
      if [[ -n "$SUBFINDER" ]]; then
        local SF="$OUTPUT_DIR/recon-external-subfinder-${domain}-$stamp.log"
        clear
        run_silent "subfinder $domain" "$SF" "$SUBFINDER" -d "$domain" -silent
        while IFS= read -r sub; do
          [[ -n "$sub" ]] && record_finding "external_subdomain" "$sub" "" '{"source":"subfinder"}'
        done < "$SF"
      fi
    done
    read -rp "Press Enter to continue..."
  fi

  clear
  echo "[recon] external check complete."
  echo "  shodan internetdb: $OUTPUT_DIR/recon-external-shodan-$stamp.json"
  echo "  findings recorded to: $OUTPUT_DIR/findings.jsonl"
  echo
  echo "Reminder: NAT-hairpin nmap is unreliable. For ground-truth external view,"
  echo "spin up a free-tier cloud VM, install nmap there, and scan your public IPs from it."
  read -rp "Press Enter to continue..."
}

# --- main loop ---

main() {
  init_targets
  check_internet
  while true; do
    local hdr="Targets: $TARGETS_FILE  |  Internet: $([[ $INTERNET_OK == 1 ]] && echo OK || echo NONE)  |  Depth: $([[ $THOROUGH == 1 ]] && echo FULL || echo QUICK)"
    mode=$(whiptail --title "Recon — internal + external" --menu \
      "$hdr\n\nFastest path: AUTO (re-detects + runs everything)" 24 100 9 \
      "AUTO"     "Auto-detect CIDRs + public IP, run INTERNAL+EXTERNAL with no prompts" \
      "TARGETS"  "View / edit recon-targets.txt manually" \
      "DEPTH"    "Toggle scan depth: QUICK vs FULL (FULL = 1-4hr per /24)" \
      "INTERNAL" "Sweep internal CIDRs (nmap + SMB + whatweb + nikto + nuclei + openvas if FULL)" \
      "EXTERNAL" "External view (Shodan/crt.sh if internet, else NAT-hairpin nmap + local DNS)" \
      "BOTH"     "Run INTERNAL then EXTERNAL" \
      "VIEW"     "View current targets" \
      "OPENVAS"  "OpenVAS / GVM info + status (install / start / scan recipe)" \
      "QUIT"     "Back to main menu" \
      3>&1 1>&2 2>&3) || break
    case "$mode" in
      AUTO)     auto_recon ;;
      TARGETS)  edit_targets ;;
      DEPTH)    choose_thoroughness ;;
      VIEW)     show_targets ;;
      INTERNAL) internal_recon ;;
      EXTERNAL) external_recon ;;
      BOTH)     internal_recon; external_recon ;;
      OPENVAS)  openvas_dispatch "$(get_targets internal_cidr | tr '\n' ' ')" "$(date +%F-%H%M)" ;;
      QUIT)     break ;;
    esac
  done
}

main
