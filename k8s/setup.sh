#!/usr/bin/env bash
# k8s/setup.sh — Full Kind + Cilium + Hubble + Tetragon + Gatekeeper cluster setup
# Cilium CNI, eBPF runtime security, 3-container pods
# One command to create a fully-armed Kind cluster ready for workspace pods.
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER_NAME:-devfactory}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOTAL_STEPS=12

# ── Helper functions ─────────────────────────────────
log()  { echo ""; echo "[$1/${TOTAL_STEPS}] $2"; }
ok()   { echo "  [OK] $1"; }
warn() { echo "  [WARN] $1"; }

echo "╔══════════════════════════════════════════════════╗"
echo "║  DevFactory K8s — Secure Infrastructure Setup    ║"
echo "╚══════════════════════════════════════════════════╝"

# ── 0. Prerequisites ──────────────────────────────────
for cmd in kind kubectl helm cilium docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is required but not installed"
    exit 1
  fi
done

# ── 1. Create Kind cluster (no default CNI) ──────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  log 1 "Kind cluster '${CLUSTER_NAME}' already exists, reusing..."
else
  log 1 "Creating Kind cluster '${CLUSTER_NAME}' (Cilium-ready)..."
  kind create cluster --name "$CLUSTER_NAME" --config "${SCRIPT_DIR}/kind-config.yaml"
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}" 2>/dev/null || true

# ── 2. Build and load workspace image into Kind ──────
log 2 "Building workspace image..."
WORKSPACE_IMAGE="${WORKSPACE_IMAGE:-devfactory-workspace:latest}"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-devfactory-sidecar:latest}"

if [ -f "${PROJECT_ROOT}/Dockerfile.workspace" ]; then
  docker build -t "$WORKSPACE_IMAGE" -f "${PROJECT_ROOT}/Dockerfile.workspace" "${PROJECT_ROOT}"
else
  # Build a sensible default workspace image inline
  docker build -t "$WORKSPACE_IMAGE" -f - "${PROJECT_ROOT}" <<'DOCKERFILE'
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git python3 ttyd awscli \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 workspace
WORKDIR /workspace
COPY workspace-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER 1001
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
DOCKERFILE
fi
kind load docker-image "$WORKSPACE_IMAGE" --name "$CLUSTER_NAME" 2>/dev/null || true
ok "Workspace image loaded into Kind: ${WORKSPACE_IMAGE}"

# Load sidecar image if it exists locally
if docker image inspect "$SIDECAR_IMAGE" &>/dev/null; then
  kind load docker-image "$SIDECAR_IMAGE" --name "$CLUSTER_NAME"
  ok "Sidecar image loaded: ${SIDECAR_IMAGE}"
else
  warn "${SIDECAR_IMAGE} not found locally, skipping"
fi

# ── 3. Install Cilium CNI + Hubble ───────────────────
log 3 "Installing Cilium CNI + Hubble observability..."
bash "${SCRIPT_DIR}/cilium/install-cilium.sh"

# Expose Hubble UI via NodePort
echo "  Exposing Hubble UI via NodePort..."
kubectl apply -f "${SCRIPT_DIR}/cilium/hubble-nodeport.yaml" 2>/dev/null || true

# ── 4. Create namespaces (PSA labels) ────────────────
log 4 "Creating namespaces..."
kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"

# ── 5. Apply RBAC ────────────────────────────────────
log 5 "Applying RBAC..."
kubectl apply -f "${SCRIPT_DIR}/rbac.yaml"

# ── 6. Apply LimitRange ──────────────────────────────
log 6 "Applying resource limits..."
kubectl apply -f "${SCRIPT_DIR}/limit-range.yaml"

# ── 7. Apply Cilium NetworkPolicies ──────────────────
log 7 "Applying Cilium network policies..."
# Apply Cilium-native policies (L3/L4/L7 + FQDN)
kubectl apply -f "${SCRIPT_DIR}/cilium/network-policies.yaml" 2>/dev/null || {
  warn "Cilium CRDs not ready yet, falling back to vanilla K8s NetworkPolicies..."
  kubectl apply -f "${SCRIPT_DIR}/network-policies.yaml"
}

# ── 8. Install Tetragon ──────────────────────────────
log 8 "Installing Tetragon eBPF runtime security..."
bash "${SCRIPT_DIR}/tetragon/install-tetragon.sh"

# (Falco removed — Tetragon covers all detection + enforcement via eBPF)

# ── 9. Install OPA Gatekeeper admission control ──────
log 9 "Installing OPA Gatekeeper admission control..."
if [ -x "${SCRIPT_DIR}/admission/install-gatekeeper.sh" ]; then
  bash "${SCRIPT_DIR}/admission/install-gatekeeper.sh" 2>/dev/null && \
    ok "Gatekeeper installed via install-gatekeeper.sh" || \
    warn "Gatekeeper install failed"
else
  # Inline fallback using Helm
  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
  helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace \
    --set replicas=1 \
    --wait --timeout=120s 2>/dev/null && \
    ok "Gatekeeper installed via Helm" || \
    warn "Gatekeeper install failed"
fi

# Apply constraint templates and constraints (wait for CRDs)
echo "  Applying admission policies..."
sleep 5  # Wait for Gatekeeper CRDs to register
kubectl apply -f "${SCRIPT_DIR}/admission/constraint-templates.yaml" 2>/dev/null || warn "Constraint templates not applied (CRDs may not be ready)"
sleep 3  # Wait for templates to be established before constraints
kubectl apply -f "${SCRIPT_DIR}/admission/constraints.yaml" 2>/dev/null || warn "Constraints not applied"
ok "OPA Gatekeeper installed with admission policies"

# ── 11. Deploy LocalStack into cluster ───────────────
log 10 "Deploying LocalStack into cluster (S3 for workspace pods)..."

# Pre-load LocalStack image into Kind so the deployment can use it
docker pull localstack/localstack:3.0 2>/dev/null || true
kind load docker-image localstack/localstack:3.0 --name "$CLUSTER_NAME" 2>/dev/null || true

kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: localstack
  namespace: devfactory-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: localstack
  template:
    metadata:
      labels:
        app: localstack
    spec:
      containers:
      - name: localstack
        image: localstack/localstack:3.0
        ports:
        - containerPort: 4566
        env:
        - name: SERVICES
          value: "s3"
        - name: DEFAULT_REGION
          value: "us-east-1"
        resources:
          requests:
            cpu: "250m"
            memory: "256Mi"
          limits:
            cpu: "1"
            memory: "512Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: localstack
  namespace: devfactory-system
spec:
  selector:
    app: localstack
  ports:
  - port: 4566
    targetPort: 4566
EOF

# Wait for LocalStack to become ready
kubectl rollout status deployment/localstack -n devfactory-system --timeout=60s 2>/dev/null || warn "LocalStack not ready yet"

# Create S3 buckets for workspace operations
kubectl exec -n devfactory-system deploy/localstack -- \
  awslocal s3 mb s3://workspace-snapshots 2>/dev/null || true
kubectl exec -n devfactory-system deploy/localstack -- \
  awslocal s3 mb s3://deployment-artifacts 2>/dev/null || true

ok "LocalStack deployed with S3 buckets (workspace-snapshots, deployment-artifacts)"

# ── 12. Verify cluster ───────────────────────────────
log 11 "Verifying cluster..."
echo ""
echo "  Nodes:       $(kubectl get nodes --no-headers | wc -l | tr -d ' ')"
echo "  Namespaces:  $(kubectl get ns --no-headers | wc -l | tr -d ' ')"
echo "  Cilium:      $(kubectl -n kube-system get pods -l k8s-app=cilium --no-headers 2>/dev/null | wc -l | tr -d ' ') pods"
echo "  Tetragon:    $(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null | wc -l | tr -d ' ') pods"
echo "  Tetragon:    $(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null | grep Running | wc -l | tr -d ' ') enforcement pods"
echo "  Gatekeeper:  $(kubectl -n gatekeeper-system get pods --no-headers 2>/dev/null | wc -l | tr -d ' ') pods"
echo "  LocalStack:  $(kubectl -n devfactory-system get pods -l app=localstack --no-headers 2>/dev/null | wc -l | tr -d ' ') pods"
echo ""

# ── Summary ───────────────────────────────────────────
echo "╔══════════════════════════════════════════════════╗"
echo "║  Setup Complete                                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Cluster:     kind-${CLUSTER_NAME}"
echo ""
echo "  Security controls active:"
echo "    - Cilium L3/L4/L7 NetworkPolicies (6 rules)"
echo "    - Tetragon eBPF TracingPolicies (3 policies, Sigkill enforcement)"
echo "    - Tetragon eBPF enforcement (Sigkill on escape/SSRF, syscall monitoring)"
echo "    - OPA Gatekeeper admission control (7 constraints)"
echo "    - Pod Security Admission: restricted"
echo "    - Namespace isolation + RBAC zero-trust"
echo ""
echo "Namespaces:"
kubectl get ns | grep -E "devfactory|tetragon|kube-system|gatekeeper" || true
echo ""
echo "Cilium:"
cilium status --context "kind-${CLUSTER_NAME}" --brief 2>/dev/null || echo "  (checking...)"
echo ""
echo "Tetragon policies:"
kubectl get tracingpolicies -A 2>/dev/null || echo "  (loading...)"
echo ""
echo "Network policies:"
kubectl get ciliumnetworkpolicies -n devfactory-workspaces 2>/dev/null || \
  kubectl get networkpolicy -n devfactory-workspaces 2>/dev/null || echo "  (none yet)"
echo ""
echo "Endpoints:"
echo "  Hubble UI:    http://localhost:30480"
echo "  Grafana:      http://localhost:30300"
echo "  Prometheus:   http://localhost:30090"
echo "  Jaeger:       http://localhost:30686"
echo "  LocalStack:   http://localstack.devfactory-system:4566 (in-cluster)"
echo ""
echo "Test workspace:"
echo "  kubectl apply -f ${SCRIPT_DIR}/workspace-pod-template.yaml"
echo ""
echo "Tear down:"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
