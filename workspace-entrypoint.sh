#!/bin/bash
set -e

# Restore from snapshot if SNAPSHOT_KEY is provided (content-addressed)
if [ -n "${SNAPSHOT_KEY:-}" ] && [ -n "${S3_ENDPOINT:-}" ]; then
  echo "[workspace-entrypoint] Restoring snapshot: ${SNAPSHOT_KEY}"
  aws --endpoint-url "${S3_ENDPOINT}" s3 cp \
    "s3://${S3_BUCKET:-workspace-snapshots}/${SNAPSHOT_KEY}" \
    /tmp/snapshot.tar.gz 2>/dev/null || true

  if [ -f /tmp/snapshot.tar.gz ]; then
    tar -xzf /tmp/snapshot.tar.gz -C /workspace
    rm -f /tmp/snapshot.tar.gz
    echo "[workspace-entrypoint] Snapshot restored successfully"
  else
    echo "[workspace-entrypoint] No snapshot found, starting fresh"
  fi
fi

echo "[workspace-entrypoint] Starting workspace services..."

# Always generate terminal credentials — never start ttyd without auth
TTYD_USER="${TTYD_USER:-workspace}"
TTYD_PASS="${TTYD_PASS:-$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
mkdir -p /workspace/.devfactory
echo "${TTYD_USER}:${TTYD_PASS}" > /workspace/.devfactory/ttyd-creds
chmod 600 /workspace/.devfactory/ttyd-creds

# Start ttyd with credentials — credential flag is mandatory
ttyd --port 8080 --writable --credential "${TTYD_USER}:${TTYD_PASS}" bash &

echo "[workspace-entrypoint] ttyd started on port 8080 (authenticated)"

# Signal readiness so backend waitForReady doesn't time out
echo "ready" > /workspace/.devfactory/status

# Keep alive
echo "[workspace-entrypoint] Workspace ready"
exec tail -f /dev/null
