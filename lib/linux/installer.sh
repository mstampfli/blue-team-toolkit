#!/usr/bin/env bash
# Tool installer, manifest-driven, dispatches per method.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

MANIFEST="$TOOLKIT_DIR/tools.json"
[[ -f "$MANIFEST" ]] || die "tools.json not found at $MANIFEST"

INSTALL_LOG="$OUTPUT_DIR/install-$(date +%F-%H%M).log"
: > "$INSTALL_LOG"

build_checklist() {
  jq -r '
    .tools[]
    | select(.linux != null)
    | [.id, ((.name | gsub("\t";" ")) + ", " + (.description | gsub("\t";" "))), (if .star then "ON" else "OFF" end)]
    | @tsv
  ' "$MANIFEST"
}

select_tools() {
  local items=()
  while IFS=$'\t' read -r id desc default; do
    items+=("$id" "$desc" "$default")
  done < <(build_checklist)
  whiptail --title "Tool Selection (★ pre-selected)" \
    --checklist "Space to toggle, Enter to confirm:" 28 110 20 \
    "${items[@]}" \
    3>&1 1>&2 2>&3
}

run_logged() {
  log "EXEC: $*"
  echo ">>> $*" | tee -a "$INSTALL_LOG"
  "$@" 2>&1 | tee -a "$INSTALL_LOG"
}

install_apt()  { run_logged sudo apt-get install -y "$1"; }
install_pipx() {
  if command -v pipx >/dev/null 2>&1; then
    run_logged pipx install "$1"
  else
    run_logged pip3 install --user --break-system-packages "$1"
  fi
}
install_url() {
  local url="$1" filename="${2:-}"
  [[ -z "$filename" ]] && filename="$(basename "$url")"
  local out="$TOOLS_DIR/$filename"
  run_logged curl -fsSL --retry 3 -o "$out" "$url"
  chmod +x "$out" 2>/dev/null || true
  echo "    -> $out" | tee -a "$INSTALL_LOG"
}
install_git() {
  local id="$1" repo="$2"
  local dir="$TOOLS_DIR/$id"
  if [[ -d "$dir/.git" ]]; then
    run_logged git -C "$dir" pull --ff-only
  else
    run_logged git clone --depth 1 "$repo" "$dir"
  fi
}
install_github_release() {
  local id="$1" repo="$2" pattern="$3"
  local api="https://api.github.com/repos/$repo/releases/latest"
  log "FETCH gh release: $repo (pattern: $pattern)"
  local url
  url=$(curl -fsSL "$api" | jq -r --arg p "$pattern" '
    .assets[] | select(.name | test($p)) | .browser_download_url' | head -1)
  if [[ -z "$url" || "$url" == "null" ]]; then
    echo "ERROR: no asset matching $pattern in $repo" | tee -a "$INSTALL_LOG"
    log "ERROR: no asset matching $pattern in $repo"
    return 1
  fi
  install_url "$url" "$(basename "$url")"
}

install_one() {
  local id="$1"
  local entry method
  entry=$(jq --arg id "$id" '.tools[] | select(.id == $id)' "$MANIFEST")
  method=$(echo "$entry" | jq -r '.linux.method // empty')
  [[ -z "$method" ]] && { echo "SKIP $id (no linux entry)"; return; }
  case "$method" in
    apt)            install_apt "$(echo "$entry" | jq -r '.linux.package')" ;;
    pip|pipx)       install_pipx "$(echo "$entry" | jq -r '.linux.package')" ;;
    url)            install_url "$(echo "$entry" | jq -r '.linux.url')" "$(echo "$entry" | jq -r '.linux.filename // empty')" ;;
    git_clone)      install_git "$id" "$(echo "$entry" | jq -r '.linux.repo')" ;;
    github_release) install_github_release "$id" "$(echo "$entry" | jq -r '.linux.repo')" "$(echo "$entry" | jq -r '.linux.pattern')" ;;
    manual)
      local note; note=$(echo "$entry" | jq -r '.linux.note')
      echo "MANUAL ($id): $note" | tee -a "$INSTALL_LOG"
      log "MANUAL: $id, $note"
      ;;
    *) echo "Unknown method '$method' for $id" | tee -a "$INSTALL_LOG" ;;
  esac
}

all_ids() {
  jq -r '.tools[] | select(.linux != null) | .id' "$MANIFEST"
}

main() {
  clear
  local mode
  mode=$(whiptail --title "Install mode" --menu "How to install?" 16 78 4 \
    "ALL"    "Install EVERY Linux tool from manifest (recommended on first run)" \
    "CUSTOM" "Pick from checklist (★ pre-selected)" \
    "QUIT"   "Back to menu" \
    3>&1 1>&2 2>&3) || return 0

  local selection=""
  case "$mode" in
    ALL)    selection="$(all_ids | tr '\n' ' ')" ;;
    CUSTOM) selection=$(select_tools) || return 0 ;;
    QUIT)   return 0 ;;
  esac
  [[ -z "$selection" ]] && return 0

  clear
  echo "[installer] installing $(echo "$selection" | wc -w) tools, output captured to $INSTALL_LOG"
  echo

  local count=0 total
  total=$(echo "$selection" | wc -w)
  for raw in $selection; do
    local id="${raw//\"/}"
    count=$((count+1))
    echo "[$count/$total] $id"
    echo "===== $id =====" >> "$INSTALL_LOG"
    # install_one's run_logged() already tees output into INSTALL_LOG;
    # silence terminal here so the screen stays a clean progress list.
    if install_one "$id" >/dev/null 2>&1; then
      log "OK: $id"
      echo "       OK"
    else
      log "FAIL: $id"
      echo "       FAIL (see $INSTALL_LOG)"
    fi
  done

  echo
  echo "[installer] complete."
  read -rp "Press Enter to return to menu..."
}

main
