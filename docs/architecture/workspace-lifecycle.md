# Workspace Lifecycle

Each project gets an isolated workspace container where the LLM agent writes files, installs packages, and runs commands. The workspace subsystem supports two backends (Docker and Kubernetes) behind a unified facade.

Source files:
- `src/server/services/workspace.ts` -- facade (routes to Docker or K8s)
- `src/server/services/docker.ts` -- Docker backend
- `src/server/services/k8s-workspace.ts` -- Kubernetes backend
- `src/server/services/snapshot.ts` -- content-addressed S3 snapshot service

## Backend Selection

The `WORKSPACE_RUNTIME` environment variable controls which backend is used:
- `docker` (default) -- local Docker daemon via `dockerode`
- `kubernetes` -- Kubernetes cluster via `@kubernetes/client-node`

The facade in `workspace.ts` lazy-imports the K8s module to avoid loading `@kubernetes/client-node` when running Docker locally.

## Facade API

All workspace operations go through these functions:

| Function | Purpose |
|----------|---------|
| `createWorkspace(projectId)` | Provision a new container, return URLs |
| `execInWorkspace(containerName, command)` | Run a shell command, return stdout/stderr/exitCode |
| `writeFileToWorkspace(containerName, filePath, content)` | Write a file (with path validation) |
| `readFileFromWorkspace(containerName, filePath)` | Read a file (with path validation) |
| `listFilesInWorkspace(containerName, dirPath?)` | List files (excludes node_modules, .git, dist) |
| `destroyWorkspace(containerName)` | Stop and remove the container |
| `getWorkspaceStatus(containerName)` | Check if the container is running |
| `checkContainerHealth(containerName)` | Detailed health: memory, CPU, PIDs, uptime |

## Docker Backend

### Container Configuration

Containers are created with:
- **Image**: `WORKSPACE_IMAGE` env var (default: `devfactory-workspace:latest`)
- **Network**: `ai-dev-factory-v2_devfactory-v2` (shared with other services)
- **Name format**: `devfactory-v2-ws-<projectId>`
- **Exposed ports**: 3000 (preview), 8080 (terminal/ttyd)

### Resource Limits

| Resource | Limit |
|----------|-------|
| Memory | 2 GB |
| CPU | 2 cores (2e9 NanoCpus) |
| PIDs | 256 |

### Security Hardening

- `SecurityOpt: ["no-new-privileges"]` -- prevents privilege escalation via setuid/setgid
- Container restarts clean up: existing container is stopped (2s grace) and force-removed before re-creation

### Traefik Integration

Each container gets Traefik labels for automatic HTTP routing through port 8090:
- `<containerName>.localhost:8090/` routes to port 3000 (app preview)
- `<containerName>.localhost:8090/ttyd` routes to port 8080 (terminal), with a strip-prefix middleware

### Ready Check

After starting a container, the Docker backend polls for `/workspace/.devfactory/status` to contain "ready". Timeout is 30 seconds. If the check times out, the container is used anyway (it may still be initializing).

### File Operations

- **Write**: Uses `tar-stream` to create an in-memory tar archive, then `container.putArchive()` to write it. Parent directories are created with `mkdir -p`.
- **Read**: Executes `cat <path>` inside the container.
- **List**: Executes `find <path> -maxdepth 3` excluding `node_modules`, `.git`, `dist`, `.devfactory`, limited to 200 entries.
- **Exec**: Uses Docker exec API with stdout/stderr demuxing. 120-second timeout.

### Health Monitoring

`checkContainerHealth` returns:
- Running state and Docker status
- Memory usage (MB) from container stats
- CPU percentage (computed from delta of total_usage / system_cpu_usage)
- PID count
- Uptime since container start

## Kubernetes Backend

### Pod Architecture

Each workspace is a **2-container pod** in the `devfactory-workspaces` namespace:

```
+--------- Pod: ws-<projectId> ----------+
|                                         |
|  +--workspace container--+  +--sidecar--+
|  | devfactory-workspace  |  | alpine    |
|  | port 3000 (preview)   |  | read-only |
|  | port 8080 (terminal)  |  | /workspace|
|  | CPU: 250m-2           |  | CPU: 50m  |
|  | Mem: 256Mi-2Gi        |  | Mem: 32Mi |
|  +-----------+-----------+  +-----+-----+
|              |                    |
|         +----+--------------------+---+
|         |  emptyDir: workspace-vol    |
|         |  (5Gi limit)                |
|         +-----------------------------+
|         |  emptyDir: tmp-vol (1Gi)    |
|         +-----------------------------+
+------------------------------------------+
```

### Security Context

Pods run with strict security settings:
- `runAsNonRoot: true`, `runAsUser: 1001`, `runAsGroup: 1001`, `fsGroup: 1001`
- `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`
- `capabilities: drop: ["ALL"]`
- Sidecar additionally has `readOnlyRootFilesystem: true`
- `automountServiceAccountToken: false` (prevents K8s API access)

### Service

A ClusterIP Service is created alongside each pod with ports 3000 and 8080, selected by the `workspace-id` label. The preview URL uses the pod IP directly.

### Exec

Commands are executed via the `@kubernetes/client-node` Exec API targeting the `workspace` container. Stdout and stderr are captured via Writable streams. 120-second timeout.

### File Operations

File writes use base64 encoding: content is encoded, piped through `base64 -d`, and redirected to the target path. This avoids issues with special characters in shell escaping.

## Path Validation

Both backends enforce identical path validation before any file operation:

1. Path must start with `/workspace`
2. After `path.resolve()`, the path must still start with `/workspace` (prevents `../` traversal)
3. Blocked patterns:
   - `/..+/` -- double-dot traversal
   - `/.git/config$` -- git credentials
   - `/.env.production$` -- production secrets

Violations throw an error with a descriptive message.

## Snapshot Service

`snapshot.ts` provides content-addressed workspace snapshots stored in S3 (LocalStack in development).

### Save Snapshot

1. Create a tar.gz of `/workspace` inside the container (excluding `node_modules`, `.git`, `dist`)
2. Download the tar via Docker `getArchive` API
3. Compute SHA-256 hash of the tar content
4. Key format: `<projectId>/<sha256>.tar.gz`
5. Check if the key already exists in S3 (deduplication via `HeadObject`)
6. Upload to S3 with `content-hash`, `project-id`, and `created-at` metadata

### Restore Snapshot

1. Download the tar from S3
2. Verify SHA-256 integrity against either the expected hash parameter or S3 metadata
3. Push the archive into the container via `putArchive`
4. Run `npm install --prefer-offline` to restore dependencies

### Verify Snapshot

A standalone `verifySnapshot(key, expectedHash)` function downloads and hashes the snapshot without restoring it, for integrity auditing.

## Related Documentation

- [Event System](event-system.md) -- workspace events (`workspace.created`, `workspace.destroyed`, `workspace.snapshot_saved`, `workspace.snapshot_restored`)
- [Data Model](data-model.md) -- `Project` model stores `containerId`, `containerName`, `snapshotKey`, `snapshotHash`
- [Infrastructure](../infrastructure/README.md) -- Docker Compose service definitions
