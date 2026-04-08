#!/usr/bin/env bash
# Install OPA Gatekeeper from official release manifests
set -euo pipefail

GATEKEEPER_VERSION="${GATEKEEPER_VERSION:-v3.15.1}"

echo "Installing OPA Gatekeeper ${GATEKEEPER_VERSION}..."
kubectl apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml"

echo "Waiting for Gatekeeper to be ready..."
kubectl -n gatekeeper-system rollout status deployment/gatekeeper-controller-manager --timeout=120s
kubectl -n gatekeeper-system rollout status deployment/gatekeeper-audit --timeout=120s

echo "Gatekeeper installed successfully"
kubectl get pods -n gatekeeper-system
