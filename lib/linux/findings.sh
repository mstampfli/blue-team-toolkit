#!/usr/bin/env bash
# View persistent findings accumulated across all hunt/triage/map runs.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

F="$OUTPUT_DIR/findings.jsonl"
if [[ ! -f "$F" ]]; then
  whiptail --msgbox "No findings.jsonl yet.\nRun option 4 (Hunt) or 6 (Map) first." 10 60
  exit 0
fi

mode=$(whiptail --title "Findings history" --menu "View mode:" 18 70 5 \
  "SUMMARY"  "Group by host+type+target — count, first/last seen" \
  "RECENT"   "Last 50 findings (raw)" \
  "BY_TYPE"  "Filter by finding type" \
  "EXPORT"   "Export deduped CSV to output/findings-summary.csv" \
  "QUIT"     "Back" \
  3>&1 1>&2 2>&3) || exit 0

case "$mode" in
  SUMMARY)
    clear
    echo "=== FINDINGS SUMMARY ($(wc -l < "$F") raw events) ==="
    echo "format: count | first_seen | last_seen | host | type | target"
    echo
    jq -s '
      group_by([.host, .type, .target])
      | map({
          host: .[0].host,
          type: .[0].type,
          target: .[0].target,
          count: length,
          first: (map(.ts) | min),
          last:  (map(.ts) | max)
        })
      | sort_by(.last) | reverse
      | .[]
      | "\(.count)\t\(.first)\t\(.last)\t\(.host)\t\(.type)\t\(.target)"
    ' -r "$F" | column -t -s$'\t' | less -RFX
    ;;
  RECENT)
    clear
    tail -50 "$F" | jq -r '"\(.ts)  [\(.host)]  \(.type)  \(.target)\(if .sha256 then "  sha256=\(.sha256[:12])…" else "" end)"' | less -RFX
    ;;
  BY_TYPE)
    types=$(jq -r '.type' "$F" | sort -u)
    items=()
    for t in $types; do
      cnt=$(grep -c "\"type\":\"$t\"" "$F")
      items+=("$t" "$cnt findings")
    done
    pick=$(whiptail --title "Pick type" --menu "Select:" 20 70 12 "${items[@]}" 3>&1 1>&2 2>&3) || exit 0
    clear
    jq -r --arg t "$pick" 'select(.type == $t) | "\(.ts)  [\(.host)]  \(.target)\(if .sha256 then "  sha256=\(.sha256[:12])…" else "" end)"' "$F" | less -RFX
    ;;
  EXPORT)
    OUT="$OUTPUT_DIR/findings-summary.csv"
    {
      echo "count,first_seen,last_seen,host,type,target,latest_sha256"
      jq -s '
        group_by([.host, .type, .target])
        | map({
            count: length,
            first: (map(.ts) | min),
            last:  (map(.ts) | max),
            host:  .[0].host,
            type:  .[0].type,
            target: .[0].target,
            sha:   ((map(.sha256) | map(select(. != null)) | last) // "")
          })
        | sort_by(.last) | reverse
        | .[]
        | [.count, .first, .last, .host, .type, .target, .sha] | @csv
      ' -r "$F"
    } > "$OUT"
    info_box "Exported to: $OUT\n\n$(wc -l < "$OUT") rows"
    ;;
  QUIT) ;;
esac
