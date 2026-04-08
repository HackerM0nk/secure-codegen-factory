# Kubernetes Runtime Security

> Infrastructure-level security controls across network policies, eBPF
> tracing, admission control, Falco monitoring, RBAC, and pod security
> context. Implemented in the `k8s/` directory.

## Namespace Architecture

All workspace pods run in the `devfactory-workspaces` namespace. The
platform control plane runs in `devfactory-system`. This separation enables
namespace-scoped policies that restrict workspaces without affecting the
control plane.

## Network Policies

Two implementations exist: vanilla Kubernetes NetworkPolicy (default) and
Cilium CiliumNetworkPolicy (when Cilium is the CNI). Cilium policies
provide FQDN-level egress filtering that vanilla NetworkPolicy cannot.

### Vanilla Kubernetes Policies (`k8s/network-policies.yaml`)

| Policy | Type | Effect |
|---|---|---|
| `deny-all-ingress` | Ingress | Default deny all ingress to workspace namespace |
| `deny-all-egress` | Egress | Default deny all egress from workspace namespace |
| `allow-dns` | Egress | Allow UDP/TCP port 53 for DNS resolution |
| `allow-registry-egress` | Egress | Allow ports 80/443 for package registry access |
| `allow-traefik-ingress` | Ingress | Allow Traefik (from devfactory-system) on ports 3000, 8080 |
| `block-metadata-endpoint` | Egress | Block 169.254.169.254/32, 100.100.100.200/32, fd00:ec2::254/128 |
| `deny-inter-pod` | Ingress | Block pod-to-pod within workspace namespace (tenant isolation) |

### Cilium Network Policies (`k8s/cilium/network-policies.yaml`)

Cilium policies replace the vanilla policies and add FQDN-level filtering.

| Policy | Type | Effect |
|---|---|---|
| `default-deny-all` | Ingress + Egress | Default deny ALL traffic |
| `allow-dns` | Egress | Allow DNS to kube-dns only (with DNS inspection) |
| `allow-package-registries` | Egress (FQDN) | FQDN allowlist for egress (see table below) |
| `allow-system-ingress` | Ingress | Allow from devfactory-system on ports 3000, 8080, 9090 |
| `block-metadata-ssrf` | Egress Deny | Block 169.254.169.254, 100.100.100.200, K8s service CIDR (except kube-dns) |
| `deny-inter-workspace` | Ingress + Egress | Block all workspace-to-workspace traffic |
| `l7-http-visibility` | Ingress | HTTP method visibility via Hubble proxy |

### FQDN Egress Allowlist (Cilium)

| Domain | Purpose |
|---|---|
| `registry.npmjs.org` | npm package registry |
| `registry.yarnpkg.com` | Yarn package registry |
| `pypi.org` | Python package index |
| `files.pythonhosted.org` | Python package downloads |
| `*.debian.org` | Debian apt repositories |
| `*.ubuntu.com` | Ubuntu apt repositories |
| `*.githubusercontent.com` | GitHub raw content |
| `github.com` | GitHub repositories |
| `api.github.com` | GitHub API |
| `objects.githubusercontent.com` | GitHub release downloads |

All other egress domains are blocked. This prevents data exfiltration to
arbitrary external hosts.

## Tetragon eBPF Tracing Policies

Three TracingPolicyNamespaced resources in `k8s/tetragon/` monitor
workspace pods at the kernel level using eBPF kprobes.

### Process Monitoring (`tracing-policy-process.yaml`)

Monitors `__arm64_sys_execve` for suspicious binary execution.

| Category | Binaries Monitored | Action |
|---|---|---|
| Container escape tools | nsenter, unshare, chroot, pivot_root | Post (alert) |
| Crypto miners | xmrig, /tmp/xmrig, cpuminer, minerd | Post (alert) |
| Network recon | nmap, masscan | Post (alert) |
| Reverse shell tools | ncat, socat | Post (alert) |
| Privilege escalation | sudo, su, passwd | Post (alert) |
| Package managers | apt, apt-get, yum, dnf | Post (alert) |

Rate limit: 1 event per second per match.

### Kill Policy (`tracing-policy-process.yaml`, second policy)

Immediately kills (SIGKILL) container escape attempts:

| Binary | Action |
|---|---|
| `/usr/bin/nsenter` | Sigkill |
| `/usr/bin/unshare` | Sigkill |
| `/usr/sbin/chroot` | Sigkill |

### File Monitoring (`tracing-policy-file.yaml`)

Monitors `__arm64_sys_openat` for sensitive file access.

| Category | Paths Monitored | Action |
|---|---|---|
| Credential files | /etc/shadow, /etc/gshadow | Post (alert) |
| Process memory | /proc/self/mem, /proc/1/mem | Post (alert) |
| Docker socket | /var/run/docker.sock, /run/containerd/containerd.sock | Post (alert) |
| Host filesystem | /host/, /rootfs/ | Post (alert) |
| K8s SA token | /var/run/secrets/kubernetes.io/, /run/secrets/kubernetes.io/ | **Sigkill** |

The K8s service account token access triggers an immediate SIGKILL -- this
is the strongest enforcement and is critical because workspace pods have
`automountServiceAccountToken: false`, so any access to this path indicates
a container escape attempt.

### Network Monitoring (`tracing-policy-network.yaml`)

Monitors `__arm64_sys_connect` for SSRF to cloud metadata endpoints.

| Target IP | Action |
|---|---|
| 169.254.169.254 | **Sigkill** |
| 100.100.100.200 | **Sigkill** |

## OPA Gatekeeper Admission Control

Seven ConstraintTemplates in `k8s/admission/constraint-templates.yaml`
define reusable admission policies. Each has a corresponding Constraint
in `k8s/admission/constraints.yaml` scoped to `devfactory-workspaces`.

| Constraint | Template | What It Enforces |
|---|---|---|
| `workspace-no-privileged` | DisallowPrivileged | No privileged containers or init containers |
| `workspace-require-limits` | RequireLimits | CPU and memory limits required on all containers |
| `workspace-require-seccomp` | RequireSeccomp | Seccomp profile required on all containers |
| `workspace-require-nonroot` | RequireNonRoot | `runAsNonRoot: true` on pod; UID != 0 on containers |
| `workspace-no-host-ns` | DisallowHostNamespaces | No hostNetwork, hostPID, or hostIPC |
| `workspace-restrict-volumes` | RestrictVolumes | No hostPath volumes |
| `workspace-no-priv-esc` | DisallowPrivilegeEscalation | `allowPrivilegeEscalation` must not be true |

## Pod Security Context

The workspace pod template (`k8s/workspace-pod-template.yaml`) enforces:

| Setting | Value | Purpose |
|---|---|---|
| `runAsNonRoot` | true | Pod-level non-root enforcement |
| `runAsUser` | 1001 | Non-root UID |
| `runAsGroup` | 1001 | Non-root GID |
| `fsGroup` | 1001 | File ownership |
| `seccompProfile.type` | RuntimeDefault | Seccomp filtering |
| `allowPrivilegeEscalation` | false | All containers |
| `capabilities.drop` | ["ALL"] | All containers drop all capabilities |
| `automountServiceAccountToken` | false | No K8s API access |

The sidecar container additionally has `readOnlyRootFilesystem: true`.

## RBAC (`k8s/rbac.yaml`)

| Service Account | Namespace | Permissions |
|---|---|---|
| `workspace-sa` | devfactory-workspaces | **NONE** -- no RoleBinding exists. Token is not mounted. |
| `workspace-controller-sa` | devfactory-system | Scoped CRUD on pods, pods/exec, pods/log, pods/status, services in workspace namespace |

## Resource Limits (`k8s/limit-range.yaml`)

| Resource | Pod Max | Container Default | Container Max |
|---|---|---|---|
| CPU | 4 cores | 2 cores (request: 500m) | 4 cores |
| Memory | 4 Gi | 2 Gi (request: 512 Mi) | 4 Gi |

## Falco (`k8s/falco/`)

Falco is deployed via Helm with Falcosidekick forwarding alerts to the
DevFactory API at `/api/security/falco-webhook`. Configuration:

| Setting | Value |
|---|---|
| Webhook endpoint | `http://host.docker.internal:4100/api/security/falco-webhook` |
| Minimum priority | warning |
| Custom fields | `source: falco`, `environment: development` |

## Related Docs

- [SIEM Engine](siem-engine.md) -- Processes runtime alerts (rule 100006)
  from Tetragon and Falco
- [Incident Response](incident-response.md) -- Automated pod termination
  on critical runtime alerts
- [Output Filter](output-filter.md) -- Application-level command blocking
  that complements kernel-level enforcement
