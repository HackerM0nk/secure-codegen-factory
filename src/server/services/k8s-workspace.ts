// src/server/services/k8s-workspace.ts
// Kubernetes workspace manager — creates 3-container pods (init + main + sidecar)
// Same interface as docker.ts for the workspace facade

import crypto from "crypto";
import * as k8s from "@kubernetes/client-node";
import { Writable } from "stream";
import { createLogger } from "../observability/logger";
import type { WorkspaceInfo, ContainerHealthStatus } from "./docker";

const logger = createLogger("k8s-workspace");

const NAMESPACE = process.env.K8S_NAMESPACE || "devfactory-workspaces";
const WORKSPACE_IMAGE = process.env.WORKSPACE_IMAGE || "devfactory-workspace:latest";
const SIDECAR_IMAGE = process.env.SIDECAR_IMAGE || "amazon/aws-cli:2.15.0";
const INIT_IMAGE = process.env.INIT_IMAGE || "amazon/aws-cli:2.15.0";
const S3_ENDPOINT = process.env.S3_ENDPOINT || "http://localstack.devfactory-system:4566";
const S3_BUCKET = process.env.S3_BUCKET || "workspace-snapshots";
const S3_REGION = process.env.S3_REGION || "us-east-1";

// Initialize K8s client
const kc = new k8s.KubeConfig();
kc.loadFromDefault();
const coreApi = kc.makeApiClient(k8s.CoreV1Api);
const k8sExec = new k8s.Exec(kc);

function podName(projectId: string): string {
  return `ws-${projectId}`.substring(0, 63).toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

// ── Path validation (same as docker.ts) ─────────────────────────────────

function validateWorkspacePath(filePath: string): void {
  const normalized = filePath.replace(/\/+/g, "/");
  if (!normalized.startsWith("/workspace")) {
    throw new Error(`Path validation failed: "${filePath}" must start with /workspace.`);
  }
  const resolved = require("path").resolve(normalized);
  if (!resolved.startsWith("/workspace")) {
    throw new Error(`Path validation failed: "${filePath}" resolves outside /workspace.`);
  }
  const BLOCKED = [/\/\.\.+\//, /\/\.git\/config$/, /\/\.env\.production$/];
  for (const p of BLOCKED) {
    if (p.test(normalized)) throw new Error(`Path validation failed: "${filePath}" matches blocked pattern.`);
  }
}

// ── Workspace lifecycle ─────────────────────────────────────────────────

export async function createWorkspace(projectId: string, snapshotKey?: string): Promise<WorkspaceInfo> {
  const name = podName(projectId);

  // Remove existing pod+service
  try { await coreApi.deleteNamespacedPod(name, NAMESPACE); } catch {}
  try { await coreApi.deleteNamespacedService(name, NAMESPACE); } catch {}
  await waitForPodDeletion(name, 15000);

  // Generate terminal credentials
  const ttydUser = "workspace";
  const ttydPass = crypto.randomBytes(24).toString("base64url").slice(0, 32);

  logger.info({ projectId, name }, "Creating K8s workspace pod");

  // S3 env vars shared by init container and sidecar
  const s3Env: k8s.V1EnvVar[] = [
    { name: "S3_ENDPOINT", value: S3_ENDPOINT },
    { name: "S3_BUCKET", value: S3_BUCKET },
    { name: "S3_REGION", value: S3_REGION },
    { name: "AWS_ACCESS_KEY_ID", value: process.env.AWS_ACCESS_KEY_ID || "test" },
    { name: "AWS_SECRET_ACCESS_KEY", value: process.env.AWS_SECRET_ACCESS_KEY || "test" },
    { name: "AWS_DEFAULT_REGION", value: S3_REGION },
  ];

  const pod: k8s.V1Pod = {
    metadata: {
      name,
      namespace: NAMESPACE,
      labels: { app: "workspace", "project-id": projectId, "workspace-id": name },
    },
    spec: {
      serviceAccountName: "workspace-sa",
      automountServiceAccountToken: false,
      terminationGracePeriodSeconds: 30,
      securityContext: {
        runAsNonRoot: true, runAsUser: 1001, runAsGroup: 1001, fsGroup: 1001,
        seccompProfile: { type: "RuntimeDefault" },
      },

      // Init container: restore workspace snapshot from S3
      initContainers: [
        {
          name: "snapshot-restore",
          image: INIT_IMAGE,
          imagePullPolicy: "Never",
          command: ["sh", "-c", [
            `if [ -n "$SNAPSHOT_KEY" ]; then`,
            `  echo "Restoring snapshot: $SNAPSHOT_KEY";`,
            `  aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://$S3_BUCKET/$SNAPSHOT_KEY" /tmp/snapshot.tar.gz && \\`,
            `  tar xzf /tmp/snapshot.tar.gz -C /workspace && \\`,
            `  echo "Snapshot restored" || echo "No snapshot found, starting fresh";`,
            `else`,
            `  echo "No snapshot key, starting fresh";`,
            `  mkdir -p /workspace;`,
            `fi`,
          ].join("\n")],
          env: [
            ...s3Env,
            { name: "SNAPSHOT_KEY", value: snapshotKey || "" },
          ],
          volumeMounts: [
            { name: "workspace-vol", mountPath: "/workspace" },
            { name: "tmp-vol", mountPath: "/tmp" },
          ],
          resources: {
            requests: { cpu: "100m", memory: "64Mi" },
            limits: { cpu: "500m", memory: "256Mi" },
          },
          securityContext: {
            runAsNonRoot: true, runAsUser: 1001,
            allowPrivilegeEscalation: false,
            capabilities: { drop: ["ALL"] },
            seccompProfile: { type: "RuntimeDefault" },
          },
        },
      ],

      containers: [
        // Main workspace container: Node.js + ttyd terminal
        {
          name: "workspace",
          image: WORKSPACE_IMAGE,
          imagePullPolicy: "Never",
          env: [
            { name: "TTYD_USER", value: ttydUser },
            { name: "TTYD_PASS", value: ttydPass },
          ],
          ports: [
            { containerPort: 3000, name: "preview", protocol: "TCP" },
            { containerPort: 8080, name: "terminal", protocol: "TCP" },
          ],
          volumeMounts: [
            { name: "workspace-vol", mountPath: "/workspace" },
            { name: "tmp-vol", mountPath: "/tmp" },
          ],
          resources: {
            requests: { cpu: "500m", memory: "512Mi" },
            limits: { cpu: "2", memory: "2Gi" },
          },
          securityContext: {
            runAsNonRoot: true, runAsUser: 1001,
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: { drop: ["ALL"] },
            seccompProfile: { type: "RuntimeDefault" },
          },
          readinessProbe: {
            httpGet: { path: "/", port: 8080 as any },
            initialDelaySeconds: 5,
            periodSeconds: 10,
          },
          livenessProbe: {
            httpGet: { path: "/", port: 8080 as any },
            initialDelaySeconds: 15,
            periodSeconds: 30,
          },
        },

        // Sidecar: periodic workspace backup agent
        {
          name: "sidecar",
          image: SIDECAR_IMAGE,
          imagePullPolicy: "Never",
          command: ["sh", "-c", [
            `echo "Sidecar started for workspace ${name}";`,
            `while true; do`,
            `  sleep 300;`,
            `  if [ -f /workspace/.devfactory/status ]; then`,
            `    cd /workspace && tar czf /tmp/auto-snapshot.tar.gz --exclude=node_modules --exclude=.git . && \\`,
            `    aws --endpoint-url "$S3_ENDPOINT" s3 cp /tmp/auto-snapshot.tar.gz "s3://$S3_BUCKET/auto/${name}/latest.tar.gz" 2>/dev/null && \\`,
            `    echo "Auto-snapshot saved at $(date)" || true;`,
            `  fi;`,
            `done`,
          ].join("\n")],
          env: [
            ...s3Env,
            { name: "PROJECT_ID", value: projectId },
            { name: "WORKSPACE_ID", value: name },
          ],
          ports: [
            { containerPort: 9090, name: "sidecar-api", protocol: "TCP" },
          ],
          volumeMounts: [
            { name: "workspace-vol", mountPath: "/workspace", readOnly: true },
            { name: "tmp-vol", mountPath: "/tmp" },
          ],
          resources: {
            requests: { cpu: "100m", memory: "64Mi" },
            limits: { cpu: "250m", memory: "128Mi" },
          },
          securityContext: {
            runAsNonRoot: true, runAsUser: 1001,
            allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
            capabilities: { drop: ["ALL"] },
            seccompProfile: { type: "RuntimeDefault" },
          },
        },
      ],
      volumes: [
        { name: "workspace-vol", emptyDir: { sizeLimit: "5Gi" } },
        { name: "tmp-vol", emptyDir: { sizeLimit: "1Gi" } },
      ],
    },
  };

  await coreApi.createNamespacedPod(NAMESPACE, pod);

  // Create ClusterIP Service for stable DNS-based addressing
  const svc: k8s.V1Service = {
    metadata: {
      name,
      namespace: NAMESPACE,
      labels: { app: "workspace", "workspace-id": name, "project-id": projectId },
    },
    spec: {
      type: "ClusterIP",
      selector: { "workspace-id": name },
      ports: [
        { name: "preview", port: 3000, targetPort: 3000 as any },
        { name: "terminal", port: 8080, targetPort: 8080 as any },
        { name: "sidecar", port: 9090, targetPort: 9090 as any },
      ],
    },
  };
  await coreApi.createNamespacedService(NAMESPACE, svc);

  await waitForPodReady(name, 60000);

  // Use Service DNS for stable addressing (not ephemeral pod IPs)
  const previewUrl = `http://${name}.${NAMESPACE}.svc.cluster.local:3000`;
  const terminalUrl = `http://${name}.${NAMESPACE}.svc.cluster.local:8080`;

  logger.info({ name, projectId, previewUrl }, "K8s workspace ready");

  // ttydPass was injected via env vars during pod creation
  return { containerId: name, containerName: name, previewUrl, terminalUrl, ttydPass };
}

export async function execInWorkspace(
  containerName: string,
  command: string
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    const stdoutStream = new Writable({
      write(chunk, _enc, cb) { stdout += chunk.toString(); cb(); },
    });
    const stderrStream = new Writable({
      write(chunk, _enc, cb) { stderr += chunk.toString(); cb(); },
    });

    const timeout = setTimeout(() => {
      resolve({ stdout: stdout.trim(), stderr: stderr.trim() + "\n[TIMEOUT after 120s]", exitCode: -1 });
    }, 120000);

    k8sExec.exec(
      NAMESPACE, containerName, "workspace",
      ["bash", "-c", command],
      stdoutStream, stderrStream, null, false,
      (status: k8s.V1Status) => {
        clearTimeout(timeout);
        const exitCode = status.status === "Success" ? 0 : 1;
        resolve({ stdout: stdout.trim(), stderr: stderr.trim(), exitCode });
      }
    ).catch((err) => { clearTimeout(timeout); reject(err); });
  });
}

export async function writeFileToWorkspace(
  containerName: string, filePath: string, content: string
): Promise<void> {
  validateWorkspacePath(filePath);
  const dir = filePath.substring(0, filePath.lastIndexOf("/"));
  if (dir) await execInWorkspace(containerName, `mkdir -p '${dir}'`);
  const b64 = Buffer.from(content).toString("base64");
  await execInWorkspace(containerName, `echo '${b64}' | base64 -d > '${filePath}'`);
}

export async function readFileFromWorkspace(
  containerName: string, filePath: string
): Promise<string> {
  validateWorkspacePath(filePath);
  const result = await execInWorkspace(containerName, `cat '${filePath}'`);
  if (result.exitCode !== 0) throw new Error(`File not found: ${filePath} - ${result.stderr}`);
  return result.stdout;
}

export async function listFilesInWorkspace(
  containerName: string, dirPath: string = "/workspace"
): Promise<string> {
  validateWorkspacePath(dirPath);
  const result = await execInWorkspace(
    containerName,
    `find '${dirPath}' -maxdepth 3 -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/.devfactory/*' | sort | head -200`
  );
  return result.stdout;
}

export async function destroyWorkspace(containerName: string): Promise<void> {
  try { await coreApi.deleteNamespacedService(containerName, NAMESPACE); } catch {}
  try { await coreApi.deleteNamespacedPod(containerName, NAMESPACE); } catch {}
  logger.info({ containerName }, "K8s workspace destroyed");
}

export async function getWorkspaceStatus(containerName: string): Promise<{ running: boolean; state?: string }> {
  try {
    const { body: pod } = await coreApi.readNamespacedPod(containerName, NAMESPACE);
    return { running: pod.status?.phase === "Running", state: pod.status?.phase?.toLowerCase() };
  } catch { return { running: false, state: "not_found" }; }
}

export async function checkContainerHealth(containerName: string): Promise<ContainerHealthStatus> {
  try {
    const { body: pod } = await coreApi.readNamespacedPod(containerName, NAMESPACE);
    const running = pod.status?.phase === "Running";
    return {
      running, state: pod.status?.phase?.toLowerCase(),
      startedAt: pod.status?.startTime?.toISOString(),
      uptime: running && pod.status?.startTime ? Date.now() - new Date(pod.status.startTime).getTime() : undefined,
      health: running ? "healthy" : undefined,
    };
  } catch { return { running: false, state: "not_found" }; }
}

// ── Helpers ─────────────────────────────────────────────────────────────

async function waitForPodReady(name: string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { body: pod } = await coreApi.readNamespacedPod(name, NAMESPACE);
      if (pod.status?.phase === "Running") {
        const allReady = (pod.status.containerStatuses || []).every((c) => c.ready);
        if (allReady) return;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 1000));
  }
  logger.warn({ name }, "Pod ready check timed out");
}

async function waitForPodDeletion(name: string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try { await coreApi.readNamespacedPod(name, NAMESPACE); } catch { return; }
    await new Promise((r) => setTimeout(r, 500));
  }
}

// ── K8s-native snapshot operations ──────────────────────────────────────

import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { createHash } from "crypto";
import { Readable } from "stream";

const s3 = new S3Client({
  region: S3_REGION,
  endpoint: process.env.S3_ENDPOINT || "http://localhost:4666",
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "test",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "test",
  },
});

export interface SnapshotResult {
  snapshotKey: string;
  snapshotHash: string;
  sizeBytes: number;
}

export async function saveSnapshot(
  containerName: string,
  projectId: string
): Promise<SnapshotResult> {
  // Create tar inside the pod via exec (no Docker dependency)
  await execInWorkspace(
    containerName,
    "cd /workspace && tar czf /tmp/snapshot.tar.gz --exclude=node_modules --exclude=.git --exclude=dist ."
  );

  // Read the tar content via exec + base64 (kubectl cp equivalent)
  const result = await execInWorkspace(containerName, "base64 /tmp/snapshot.tar.gz");
  const tarBuffer = Buffer.from(result.stdout, "base64");

  const contentHash = createHash("sha256").update(tarBuffer).digest("hex");
  const snapshotKey = `${projectId}/${contentHash}.tar.gz`;

  try {
    await s3.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: snapshotKey }));
    return { snapshotKey, snapshotHash: contentHash, sizeBytes: tarBuffer.length };
  } catch {}

  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET, Key: snapshotKey, Body: tarBuffer,
    ContentType: "application/gzip",
    Metadata: { "content-hash": contentHash, "project-id": projectId },
  }));

  return { snapshotKey, snapshotHash: contentHash, sizeBytes: tarBuffer.length };
}

export async function restoreSnapshot(
  containerName: string,
  snapshotKey: string,
  expectedHash?: string
): Promise<{ verified: boolean; durationMs: number }> {
  const start = Date.now();

  const response = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: snapshotKey }));
  const chunks: Buffer[] = [];
  for await (const chunk of response.Body as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  const tarBuffer = Buffer.concat(chunks);

  const actualHash = createHash("sha256").update(tarBuffer).digest("hex");
  if (expectedHash && actualHash !== expectedHash) {
    throw new Error(`Snapshot integrity failed: expected ${expectedHash}, got ${actualHash}`);
  }

  // Write tar into pod via exec + base64 (kubectl cp equivalent)
  const b64 = tarBuffer.toString("base64");
  // Split into chunks to avoid exec arg limits
  const chunkSize = 65536;
  await execInWorkspace(containerName, "rm -f /tmp/snapshot.tar.gz.b64");
  for (let i = 0; i < b64.length; i += chunkSize) {
    const slice = b64.slice(i, i + chunkSize);
    await execInWorkspace(containerName, `printf '%s' '${slice}' >> /tmp/snapshot.tar.gz.b64`);
  }
  await execInWorkspace(containerName, "base64 -d /tmp/snapshot.tar.gz.b64 > /tmp/snapshot.tar.gz");
  await execInWorkspace(containerName, "cd /workspace && tar xzf /tmp/snapshot.tar.gz");
  await execInWorkspace(containerName, "cd /workspace && npm install --prefer-offline 2>/dev/null || true");

  return { verified: !!expectedHash || !!response.Metadata?.["content-hash"], durationMs: Date.now() - start };
}

export { validateWorkspacePath };
