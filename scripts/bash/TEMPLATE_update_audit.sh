#!/usr/bin/env bash
# Audits available updates and writes a simple report.

set -euo pipefail
OUT="update_audit_$(date -u +%F).txt"

echo "==== Update Audit $(date -u) ====" > "$OUT"
if command -v apt >/dev/null; then
  apt update >> "$OUT" 2>&1 || true
  apt list --upgradable >> "$OUT" 2>&1 || true
elif command -v dnf >/dev/null; then
  dnf check-update >> "$OUT" 2>&1 || true
fi

echo "Report written to $OUT"
