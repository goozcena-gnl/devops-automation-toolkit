# Linux Incident Snapshot

The native Bash collector creates a read-only, bounded host snapshot. It does not collect environment variables, application configuration, private keys, or complete application logs.

```bash
scripts/linux/linux-triage.sh \
  --output linux-report.json \
  --bundle linux-support.zip \
  --timeout 8 \
  --process-limit 25
```

Journal collection is opt-in:

```bash
scripts/linux/linux-triage.sh --include-journal --max-log-lines 200
```

## Analysis

The collector evaluates load relative to CPU count, available memory, swap utilization, filesystem and inode pressure, failed systemd units, uninterruptible processes, and bounded kernel signatures for OOM or I/O errors. Missing collectors make the report partial rather than silently successful.

The optional ZIP contains the normalized report and sanitized, size-bounded evidence files with mode `0600`.
