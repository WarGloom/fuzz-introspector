#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage:
  benchmarks/collect_report_metrics.sh <report.log> [output_dir]

Extracts report debug-loader metrics from a fuzz-introspector report log:
- [debug-load] stage timings
- shard progress cadence ("Shard load progress for ...")

Outputs:
- debug_load_stages.csv
- shard_progress_cadence.csv
- summary.md
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 1
fi

LOG_FILE="$1"
if [[ ! -f "$LOG_FILE" ]]; then
  echo "Missing log file: $LOG_FILE" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_OUT_DIR="${SCRIPT_DIR}/results/report_metrics_$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${2:-$DEFAULT_OUT_DIR}"

mkdir -p "$OUT_DIR"

STAGE_CSV="${OUT_DIR}/debug_load_stages.csv"
CADENCE_CSV="${OUT_DIR}/shard_progress_cadence.csv"
SUMMARY_MD="${OUT_DIR}/summary.md"

echo "line_no,timestamp,stage,elapsed_sec,files,types,functions,rss_mb" > "${STAGE_CSV}"

awk '
function kv(name, regex, parts) {
  regex = name "=([^ ]+)"
  if (match($0, regex, parts)) {
    return parts[1]
  }
  return ""
}
$0 ~ /\[debug-load\] stage=[^ ]+ elapsed=[0-9.]+s/ {
  ts = ""
  if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ &&
      $2 ~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+$/) {
    ts = $1 " " $2
  }
  stage = kv("stage")
  elapsed = kv("elapsed")
  sub(/s$/, "", elapsed)
  files = kv("files")
  types = kv("types")
  functions = kv("functions")
  rss = kv("rss_mb")
  printf "%d,%s,%s,%s,%s,%s,%s,%s\n",
         NR, ts, stage, elapsed, files, types, functions, rss
}
' "$LOG_FILE" >> "${STAGE_CSV}"

echo "line_no,timestamp,category,loaded,total,delta_since_prev_sec" > "${CADENCE_CSV}"

awk '
function parse_epoch(date_str, time_str, date_parts, time_parts, sec_parts, epoch, ms) {
  if (date_str !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/) {
    return -1
  }
  if (time_str !~ /^[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?$/) {
    return -1
  }
  split(date_str, date_parts, "-")
  split(time_str, time_parts, ":")
  ms = 0
  if (index(time_parts[3], ".") > 0) {
    split(time_parts[3], sec_parts, ".")
    time_parts[3] = sec_parts[1]
    ms = ("0." sec_parts[2]) + 0
  }
  epoch = mktime(sprintf("%s %s %s %s %s %s",
                         date_parts[1], date_parts[2], date_parts[3],
                         time_parts[1], time_parts[2], time_parts[3]))
  if (epoch < 0) {
    return -1
  }
  return epoch + ms
}
{
  if (match($0, /Shard load progress for ([^:]+): ([0-9]+)\/([0-9]+)/, parts)) {
    ts = ""
    epoch = -1
    if ($1 ~ /^[0-9]{4}-/ && $2 ~ /^[0-9]{2}:/) {
      ts = $1 " " $2
      epoch = parse_epoch($1, $2)
    }
    category = parts[1]
    loaded = parts[2] + 0
    total = parts[3] + 0
    delta = ""
    if (epoch >= 0 && (category in prev_epoch)) {
      delta = sprintf("%.6f", epoch - prev_epoch[category])
    }
    if (epoch >= 0) {
      prev_epoch[category] = epoch
    }
    printf "%d,%s,%s,%d,%d,%s\n", NR, ts, category, loaded, total, delta
  }
}
' "$LOG_FILE" >> "${CADENCE_CSV}"

STAGE_ROWS=$(( $(wc -l < "${STAGE_CSV}") - 1 ))
CADENCE_ROWS=$(( $(wc -l < "${CADENCE_CSV}") - 1 ))

{
  echo "# Report Metrics Summary"
  echo
  echo "- Source log: \`${LOG_FILE}\`"
  echo "- Generated (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "- Stage entries: ${STAGE_ROWS}"
  echo "- Shard progress entries: ${CADENCE_ROWS}"
  echo

  echo "## Debug-load stage timings"
  if [[ "${STAGE_ROWS}" -eq 0 ]]; then
    echo
    echo "No \`[debug-load]\` stage lines found."
  else
    echo
    echo "| Stage | Samples | Total (s) | Avg (s) | Min (s) | Max (s) |"
    echo "| --- | ---: | ---: | ---: | ---: | ---: |"
    awk -F, '
      NR == 1 { next }
      $3 != "" && $4 != "" {
        stage = $3
        elapsed = $4 + 0
        count[stage] += 1
        total[stage] += elapsed
        if (!(stage in min) || elapsed < min[stage]) {
          min[stage] = elapsed
        }
        if (!(stage in max) || elapsed > max[stage]) {
          max[stage] = elapsed
        }
      }
      END {
        for (stage in count) {
          avg = total[stage] / count[stage]
          printf "| %s | %d | %.6f | %.6f | %.6f | %.6f |\n",
                 stage, count[stage], total[stage], avg, min[stage], max[stage]
        }
      }
    ' "${STAGE_CSV}" | sort
  fi

  echo
  echo "## Shard progress cadence"
  if [[ "${CADENCE_ROWS}" -eq 0 ]]; then
    echo
    echo "No shard progress lines found."
  else
    echo
    echo "| Category | Events | Intervals | Avg delta (s) | Max delta (s) | Final progress |"
    echo "| --- | ---: | ---: | ---: | ---: | --- |"
    awk -F, '
      NR == 1 { next }
      $3 != "" {
        category = $3
        events[category] += 1
        final_loaded[category] = $4 + 0
        final_total[category] = $5 + 0
        if ($6 != "") {
          delta = $6 + 0
          interval_count[category] += 1
          delta_total[category] += delta
          if (!(category in max_delta) || delta > max_delta[category]) {
            max_delta[category] = delta
          }
        }
      }
      END {
        for (category in events) {
          avg = 0
          max = 0
          if (interval_count[category] > 0) {
            avg = delta_total[category] / interval_count[category]
            max = max_delta[category]
          }
          printf "| %s | %d | %d | %.6f | %.6f | %d/%d |\n",
                 category, events[category], interval_count[category],
                 avg, max, final_loaded[category], final_total[category]
        }
      }
    ' "${CADENCE_CSV}" | sort
  fi

  echo
  echo "## Artifacts"
  echo
  echo "- \`$(basename "${STAGE_CSV}")\`"
  echo "- \`$(basename "${CADENCE_CSV}")\`"
  echo "- \`$(basename "${SUMMARY_MD}")\`"
} > "${SUMMARY_MD}"

echo "Wrote: ${STAGE_CSV}"
echo "Wrote: ${CADENCE_CSV}"
echo "Wrote: ${SUMMARY_MD}"
