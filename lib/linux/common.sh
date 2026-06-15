#!/usr/bin/env bash
# Shared helpers for Linux scripts.

die() { echo "ERROR: $*" >&2; exit 1; }

log() {
  local ts msg
  ts="$(date +'%F %T')"
  msg="$*"
  echo "[$ts] [$(hostname)] $msg" >> "${LOG_FILE:-/tmp/blueteam-toolkit.log}"
}

confirm_box() { whiptail --yesno "$1" 12 78; }
info_box()    { whiptail --msgbox "$1" 14 78; }

# ensure_extracted <archive_glob> <binary_name>
# Extracts a downloaded archive in $TOOLS_DIR if not already extracted.
# Echoes the path to the first matching executable (or empty if nothing found).
ensure_extracted() {
  local pattern="$1" binary_name="$2"
  local archive
  archive=$(compgen -G "${TOOLS_DIR:-/tmp}/$pattern" 2>/dev/null | head -1)
  [[ -z "$archive" ]] && return 1
  local extract_dir="${TOOLS_DIR}/${binary_name}-extracted"
  if [[ ! -d "$extract_dir" || -z "$(ls -A "$extract_dir" 2>/dev/null)" ]]; then
    mkdir -p "$extract_dir"
    case "$archive" in
      *.zip)         unzip -q -o "$archive" -d "$extract_dir" 2>/dev/null ;;
      *.tar.gz|*.tgz) tar -xzf "$archive" -C "$extract_dir" 2>/dev/null ;;
      *.tar.xz)      tar -xJf "$archive" -C "$extract_dir" 2>/dev/null ;;
      *.tar)         tar -xf  "$archive" -C "$extract_dir" 2>/dev/null ;;
    esac
  fi
  local bin
  bin=$(find "$extract_dir" -type f -name "$binary_name" 2>/dev/null | head -1)
  [[ -n "$bin" ]] && chmod +x "$bin" 2>/dev/null
  echo "$bin"
}

# run_silent <label> <logfile> <cmd...>
# Runs cmd in background, captures all output to logfile, prints a heartbeat
# every 30s with elapsed time, log size + growth, and last log line.
# Caller can `clear` first if they want a clean screen.
run_silent() {
  local label="$1" logfile="$2"; shift 2
  echo "[$label] running -> $logfile"
  echo "[$label] heartbeat every 30s, if log size stops growing AND tail line is unchanged across two beats, it's stuck"
  echo
  log "Running $label -> $logfile"
  local t0=$SECONDS

  ( "$@" >"$logfile" 2>&1 ) &
  local pid=$!

  local last_size=0 last_tail="" size growth elapsed last
  while kill -0 "$pid" 2>/dev/null; do
    # short bursts so we react fast when child exits
    for _ in 1 2 3 4 5 6; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 5
    done
    kill -0 "$pid" 2>/dev/null || break
    elapsed=$((SECONDS - t0))
    size=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
    growth=$((size - last_size))
    last=$(tail -n 1 "$logfile" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r' | head -c 80)
    [[ -z "$last" ]] && last="(no output yet)"
    local marker=""
    [[ "$growth" -eq 0 && "$last" == "$last_tail" ]] && marker="  ⚠ NO PROGRESS"
    printf '[%s] alive: %ds elapsed, log=%dB (+%dB), tail: %s%s\n' \
      "$label" "$elapsed" "$size" "$growth" "$last" "$marker"
    last_size=$size; last_tail="$last"
  done

  wait "$pid" 2>/dev/null
  local rc=$? dt=$((SECONDS - t0))
  echo
  echo "[$label] done in ${dt}s (rc=$rc)"
  log "$label done in ${dt}s rc=$rc"
  return $rc
}

# record_finding <type> <target> [sha256] [extra_json_string]
# Appends one JSON-line record to $OUTPUT_DIR/findings.jsonl so noteworthy
# hits persist across runs. Read with lib/linux/findings.sh.
record_finding() {
  local type="$1" target="${2:-}" sha="${3:-}" extra="${4:-{}}"
  local file="${OUTPUT_DIR:-/tmp}/findings.jsonl"
  jq -nc \
    --arg ts     "$(date -u +%FT%TZ)" \
    --arg host   "$(hostname)" \
    --arg type   "$type" \
    --arg target "$target" \
    --arg sha    "$sha" \
    --argjson extra "$extra" \
    '{ts:$ts, host:$host, type:$type, target:$target,
      sha256:(if $sha=="" then null else $sha end)} + $extra' \
    >> "$file" 2>/dev/null
}
