#!/usr/bin/env bash
# k8s/cilium/install-cilium.sh — Install Cilium CNI + Hubble observability into Kind
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER_NAME:-devfactory}"

echo "=== Installing Cilium CNI ==="

# Install Cilium with Hubble enabled
cilium install \
  --context "kind-${CLUSTER_NAME}" \
  --set kubeProxyReplacement=false \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.enabled=true \
  --set hubble.metrics.enableOpenMetrics=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,source_workload\,destination_ip\,destination_namespace\,destination_workload\,traffic_direction}" \
  --set ipam.mode=kubernetes \
  --set operator.replicas=1

echo "Waiting for Cilium to be ready..."
cilium status --wait --context "kind-${CLUSTER_NAME}"

echo ""
echo "=== Cilium Status ==="
cilium status --context "kind-${CLUSTER_NAME}"

echo ""
echo "=== Hubble Status ==="
# Verify Hubble relay is running
kubectl get pods -n kube-system -l k8s-app=hubble-relay --context "kind-${CLUSTER_NAME}" 2>/dev/null || true
kubectl get pods -n kube-system -l k8s-app=hubble-ui --context "kind-${CLUSTER_NAME}" 2>/dev/null || true

echo ""
echo "Cilium + Hubble installation complete."
echo "To access Hubble UI: kubectl port-forward -n kube-system svc/hubble-ui 12000:80"
echo "Or via NodePort: http://localhost:30480 (after applying hubble-nodeport.yaml)"
