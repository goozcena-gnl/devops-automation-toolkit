#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -Eeuo pipefail
IFS=$'\n\t'

OUTPUT="linux-triage-report.json"
BUNDLE=""
TIMEOUT_SECONDS=8
MAX_LOG_LINES=200
PROCESS_LIMIT=25
INCLUDE_JOURNAL=false
THRESHOLD="high"

usage() {
  cat <<'EOF'
Usage: linux-triage.sh [options]

Read-only Linux incident snapshot with bounded collection and deterministic
resource-pressure findings. Raw environment variables and application secrets
are never collected.

Options:
  --output PATH                 JSON report path
  --bundle PATH                 Optional sanitized ZIP support bundle
  --timeout SECONDS             Per-command timeout (default: 8)
  --max-log-lines NUMBER        Maximum journal/kernel lines (default: 200)
  --process-limit NUMBER        Maximum process rows (default: 25)
  --include-journal             Include bounded error-priority journal evidence
  --severity-threshold LEVEL    info|low|medium|high|critical (default: high)
  -h, --help                    Show help
EOF
}

while (($# > 0)); do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo "--output requires a path" >&2; exit 2; }
      OUTPUT=$2; shift 2 ;;
    --bundle)
      [[ $# -ge 2 ]] || { echo "--bundle requires a path" >&2; exit 2; }
      BUNDLE=$2; shift 2 ;;
    --timeout)
      [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || { echo "--timeout requires a positive integer" >&2; exit 2; }
      TIMEOUT_SECONDS=$2; shift 2 ;;
    --max-log-lines)
      [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || { echo "--max-log-lines requires a positive integer" >&2; exit 2; }
      MAX_LOG_LINES=$2; shift 2 ;;
    --process-limit)
      [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || { echo "--process-limit requires a positive integer" >&2; exit 2; }
      PROCESS_LIMIT=$2; shift 2 ;;
    --include-journal)
      INCLUDE_JOURNAL=true; shift ;;
    --severity-threshold)
      [[ $# -ge 2 && $2 =~ ^(info|low|medium|high|critical)$ ]] || { echo "invalid severity threshold" >&2; exit 2; }
      THRESHOLD=$2; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 is required for safe JSON serialization" >&2; exit 3; }

umask 077
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/devops-toolkit-linux.XXXXXX")
cleanup() { rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT INT TERM

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PARTIAL=false
ERRORS_FILE="$TMP_DIR/errors.txt"
: > "$ERRORS_FILE"

have_timeout=false
if command -v timeout >/dev/null 2>&1; then have_timeout=true; fi

capture() {
  local name=$1
  shift
  local target="$TMP_DIR/$name.txt"
  if [[ "$have_timeout" == true ]]; then
    if ! timeout "${TIMEOUT_SECONDS}s" "$@" >"$target" 2>>"$ERRORS_FILE"; then
      PARTIAL=true
      printf '%s\n' "$name" >> "$TMP_DIR/failed-collectors.txt"
    fi
  else
    if ! "$@" >"$target" 2>>"$ERRORS_FILE"; then
      PARTIAL=true
      printf '%s\n' "$name" >> "$TMP_DIR/failed-collectors.txt"
    fi
  fi
  chmod 600 "$target" 2>/dev/null || true
}

available_commands=()
missing_commands=()
for command_name in uname uptime free df ps ss ip systemctl journalctl docker podman kubectl lsblk vmstat; do
  if command -v "$command_name" >/dev/null 2>&1; then
    available_commands+=("$command_name")
  else
    missing_commands+=("$command_name")
  fi
done

capture uname uname -a
capture uptime uptime
if command -v free >/dev/null 2>&1; then capture memory free -b; fi
if command -v df >/dev/null 2>&1; then
  capture disk df -P -B1
  capture inodes df -Pi
fi
if command -v ps >/dev/null 2>&1; then
  capture processes ps -eo pid,ppid,user,stat,pcpu,pmem,etimes,comm --sort=-pcpu
  capture blocked-processes ps -eo pid,ppid,user,stat,etimes,comm
fi
if command -v ss >/dev/null 2>&1; then capture sockets ss -H -lntup; fi
if command -v ip >/dev/null 2>&1; then
  capture interfaces ip -brief address
  capture routes ip route show
fi
if command -v systemctl >/dev/null 2>&1; then capture failed-units systemctl --failed --no-legend --plain; fi
if command -v lsblk >/dev/null 2>&1; then capture block-devices lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,RO; fi
if command -v vmstat >/dev/null 2>&1; then capture vmstat vmstat 1 2; fi
if [[ -r /etc/resolv.conf ]]; then cp -- /etc/resolv.conf "$TMP_DIR/resolv.conf.txt"; chmod 600 "$TMP_DIR/resolv.conf.txt"; fi
if [[ -r /proc/loadavg ]]; then cp -- /proc/loadavg "$TMP_DIR/loadavg.txt"; fi
if [[ -r /proc/meminfo ]]; then cp -- /proc/meminfo "$TMP_DIR/meminfo.txt"; fi
if [[ -r /proc/uptime ]]; then cp -- /proc/uptime "$TMP_DIR/proc-uptime.txt"; fi
if [[ -r /proc/pressure/cpu ]]; then cp -- /proc/pressure/cpu "$TMP_DIR/pressure-cpu.txt"; fi
if [[ -r /proc/pressure/memory ]]; then cp -- /proc/pressure/memory "$TMP_DIR/pressure-memory.txt"; fi
if [[ -r /proc/pressure/io ]]; then cp -- /proc/pressure/io "$TMP_DIR/pressure-io.txt"; fi

if [[ "$INCLUDE_JOURNAL" == true ]] && command -v journalctl >/dev/null 2>&1; then
  capture journal-errors journalctl -b -p err --no-pager -n "$MAX_LOG_LINES"
  capture kernel-errors journalctl -k -b -p warning --no-pager -n "$MAX_LOG_LINES"
elif command -v dmesg >/dev/null 2>&1; then
  if [[ "$have_timeout" == true ]]; then
    timeout "${TIMEOUT_SECONDS}s" dmesg --level=err,warn 2>/dev/null | tail -n "$MAX_LOG_LINES" > "$TMP_DIR/kernel-errors.txt" || PARTIAL=true
  else
    dmesg --level=err,warn 2>/dev/null | tail -n "$MAX_LOG_LINES" > "$TMP_DIR/kernel-errors.txt" || PARTIAL=true
  fi
fi

if command -v docker >/dev/null 2>&1; then capture docker-info docker info --format '{{json .}}'; fi
if command -v podman >/dev/null 2>&1; then capture podman-info podman info --format json; fi

export STARTED_AT OUTPUT BUNDLE TMP_DIR PARTIAL PROCESS_LIMIT THRESHOLD INCLUDE_JOURNAL
AVAILABLE_COMMANDS=$(printf '%s\n' "${available_commands[@]-}")
MISSING_COMMANDS=$(printf '%s\n' "${missing_commands[@]-}")
export AVAILABLE_COMMANDS MISSING_COMMANDS

python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TMP = Path(os.environ["TMP_DIR"])
OUTPUT = Path(os.environ["OUTPUT"])
BUNDLE = Path(os.environ["BUNDLE"]) if os.environ.get("BUNDLE") else None
PROCESS_LIMIT = int(os.environ["PROCESS_LIMIT"])
THRESHOLD = os.environ["THRESHOLD"]
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SECRET = re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+\S+|(?:token|password|secret|api[_-]?key)\s*[=:]\s*\S+)")


def read(name: str) -> str:
    path = TMP / f"{name}.txt"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def sanitize(text: str) -> str:
    return SECRET.sub("[REDACTED]", text)


def lines_env(name: str) -> list[str]:
    return [line for line in os.environ.get(name, "").splitlines() if line]


findings: list[dict[str, object]] = []


def finding(identifier: str, severity: str, title: str, summary: str, recommendation: str) -> None:
    digest = hashlib.sha256(f"{identifier}\x1flinux-triage\x1f{title}\x1flocal-linux-host".encode()).hexdigest()
    findings.append({
        "id": identifier,
        "tool": "linux-triage",
        "category": "linux-diagnostics",
        "severity": severity,
        "confidence": "high",
        "title": title,
        "description": "Read-only host evidence indicates a potential Linux reliability concern.",
        "recommendation": recommendation,
        "fingerprint": f"sha256:{digest}",
        "resource": {"type": "LinuxHost", "name": "local-linux-host"},
        "evidence": {"summary": sanitize(summary)[:500]},
        "references": [],
        "suppressed": False,
    })


cpu_count = os.cpu_count() or 1
load_text = read("loadavg").strip().split()
load_1 = float(load_text[0]) if load_text else 0.0
if load_1 > cpu_count * 1.5:
    finding("LINUX-LOAD-HIGH", "high", "System load materially exceeds CPU capacity", f"load_1m={load_1}; cpu_count={cpu_count}", "Inspect CPU consumers, uninterruptible tasks, I/O pressure, and runnable queue growth.")
elif load_1 > cpu_count:
    finding("LINUX-LOAD-ELEVATED", "medium", "System load exceeds logical CPU count", f"load_1m={load_1}; cpu_count={cpu_count}", "Correlate load with CPU, I/O wait, blocked processes, and workload changes.")

meminfo: dict[str, int] = {}
for line in read("meminfo").splitlines():
    if ":" not in line:
        continue
    key, raw = line.split(":", 1)
    match = re.search(r"(\d+)", raw)
    if match:
        meminfo[key] = int(match.group(1)) * 1024
mem_total = meminfo.get("MemTotal", 0)
mem_available = meminfo.get("MemAvailable", 0)
swap_total = meminfo.get("SwapTotal", 0)
swap_free = meminfo.get("SwapFree", 0)
if mem_total and mem_available / mem_total < 0.1:
    finding("LINUX-MEMORY-PRESSURE", "high", "Available memory is below 10 percent", f"available_bytes={mem_available}; total_bytes={mem_total}", "Inspect top memory consumers, cgroup limits, reclaim pressure, OOM events, and workload growth.")
if swap_total and (swap_total - swap_free) / swap_total > 0.8:
    finding("LINUX-SWAP-HIGH", "medium", "Swap utilization exceeds 80 percent", f"used_bytes={swap_total - swap_free}; total_bytes={swap_total}", "Review sustained memory pressure and whether swapped workloads are latency sensitive.")

filesystems: list[dict[str, object]] = []
for line in read("disk").splitlines()[1:]:
    parts = line.split()
    if len(parts) < 6 or not parts[-2].endswith("%"):
        continue
    usage = int(parts[-2].rstrip("%"))
    mount = parts[-1]
    filesystems.append({"mount": mount, "usage_percent": usage})
    if usage >= 95:
        finding("LINUX-DISK-CRITICAL", "critical", f"Filesystem `{mount}` is at least 95 percent full", f"usage_percent={usage}", "Free space safely, rotate bounded logs, identify growth, and confirm inode availability before services fail.")
    elif usage >= 90:
        finding("LINUX-DISK-HIGH", "high", f"Filesystem `{mount}` is at least 90 percent full", f"usage_percent={usage}", "Identify the largest safe-to-remove data and prevent further unbounded growth.")
for line in read("inodes").splitlines()[1:]:
    parts = line.split()
    if len(parts) < 6 or not parts[-2].endswith("%"):
        continue
    usage = int(parts[-2].rstrip("%"))
    mount = parts[-1]
    if usage >= 90:
        finding("LINUX-INODE-HIGH", "high", f"Filesystem `{mount}` has high inode consumption", f"inode_usage_percent={usage}", "Locate directories with excessive small files and correct retention or cleanup behavior.")

failed_units = [line for line in read("failed-units").splitlines() if line.strip()]
if failed_units:
    finding("LINUX-SYSTEMD-FAILED", "high", "One or more systemd units are failed", f"failed_units={len(failed_units)}; sample={failed_units[:5]}", "Inspect unit status, bounded journal evidence, dependencies, permissions, and recent configuration changes.")

blocked = []
for line in read("blocked-processes").splitlines()[1:]:
    parts = line.split(None, 5)
    if len(parts) >= 4 and "D" in parts[3]:
        blocked.append(line)
if blocked:
    finding("LINUX-BLOCKED-PROCESSES", "high", "Processes are stuck in uninterruptible sleep", f"count={len(blocked)}; sample={blocked[:5]}", "Investigate storage, network filesystems, device health, kernel messages, and I/O latency.")

kernel = read("kernel-errors")
if re.search(r"(?i)(out of memory|oom-killer|killed process)", kernel):
    finding("LINUX-OOM-EVENT", "critical", "Kernel evidence contains an out-of-memory event", "OOM signature found in bounded kernel evidence", "Identify the killed workload, memory growth, cgroup limits, and capacity or leak remediation.")
if re.search(r"(?i)(i/o error|buffer i/o|filesystem error|ext4-fs error|xfs.*error)", kernel):
    finding("LINUX-IO-ERROR", "critical", "Kernel evidence contains storage or filesystem errors", "I/O error signature found in bounded kernel evidence", "Protect data, inspect device health and filesystem state, and plan recovery before further writes.")

missing = lines_env("MISSING_COMMANDS")
partial = os.environ.get("PARTIAL") == "true" or bool((TMP / "failed-collectors.txt").exists())
if missing:
    partial = True
    finding("LINUX-CAPABILITY-MISSING", "low", "Some optional diagnostic commands are unavailable", f"missing_commands={missing}", "Install only the diagnostic utilities appropriate for this host image and operational model.")

process_rows = read("processes").splitlines()
process_sample = process_rows[: PROCESS_LIMIT + 1]
counts = Counter(str(item["severity"]) for item in findings)
status = "fail" if any(SEVERITY_RANK[str(item["severity"])] >= SEVERITY_RANK[THRESHOLD] for item in findings) else ("warning" if findings or partial else "pass")
summary = {name: counts.get(name, 0) for name in SEVERITY_RANK}
summary.update({"suppressed": 0, "total": len(findings)})

payload = {
    "schema_version": "1.0",
    "metadata": {
        "tool": "linux-triage",
        "tool_version": "1.0.0",
        "started_at": os.environ["STARTED_AT"],
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": "local-linux-host",
        "partial": partial,
        "capabilities": ["cpu-load", "memory", "filesystems", "processes", "systemd", "network", "kernel-evidence", "sanitized-bundle"],
    },
    "findings": findings,
    "status": status,
    "summary": summary,
    "extensions": {
        "host": {
            "cpu_count": cpu_count,
            "load_1m": load_1,
            "memory_total_bytes": mem_total,
            "memory_available_bytes": mem_available,
            "swap_total_bytes": swap_total,
            "filesystems": filesystems,
            "failed_systemd_units": len(failed_units),
            "blocked_processes": len(blocked),
            "available_commands": lines_env("AVAILABLE_COMMANDS"),
            "missing_commands": missing,
        },
        "process_sample": process_sample,
        "journal_included": os.environ.get("INCLUDE_JOURNAL") == "true",
    },
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
temporary = OUTPUT.with_name(f".{OUTPUT.name}.tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(OUTPUT)
print(OUTPUT)

if BUNDLE:
    BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    bundle_temp = BUNDLE.with_name(f".{BUNDLE.name}.tmp")
    with zipfile.ZipFile(bundle_temp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(payload, indent=2) + "\n")
        for path in sorted(TMP.glob("*.txt")):
            if path.name in {"errors.txt"}:
                continue
            content = sanitize(path.read_text(encoding="utf-8", errors="replace"))
            archive.writestr(f"evidence/{path.name}", content[:1_000_000])
    bundle_temp.chmod(0o600)
    bundle_temp.replace(BUNDLE)
    print(f"bundle={BUNDLE}")
PY
