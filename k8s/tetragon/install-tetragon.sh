#!/usr/bin/env bash
# Install Cilium Tetragon via Helm — eBPF-based runtime security
# Tetragon replaces Falco: it's eBPF-native, can enforce (Sigkill), lower overhead
set -euo pipefail

# Add Cilium Helm repo
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon
helm upgrade --install tetragon cilium/tetragon \
  --namespace tetragon \
  --create-namespace \
  --set tetragon.exportFilename=/var/log/tetragon/tetragon.log \
  --set tetragon.exportFileMaxSizeMB=100 \
  --set tetragon.exportFileRotationInterval=24h

echo "Waiting for Tetragon to be ready..."
kubectl -n tetragon rollout status daemonset/tetragon --timeout=120s

echo "Tetragon installed. Applying tracing policies..."
kubectl apply -f "$(dirname "$0")/tracing-policy-process.yaml"
kubectl apply -f "$(dirname "$0")/tracing-policy-file.yaml"
kubectl apply -f "$(dirname "$0")/tracing-policy-network.yaml"

echo ""
echo "Tetragon installed and policies applied:"
kubectl get tracingpolicies -A 2>/dev/null || echo "(TracingPolicy CRD may take a moment)"
kubectl get pods -n tetragon
