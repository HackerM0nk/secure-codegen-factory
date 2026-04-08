// src/server/services/docker.ts
// Docker workspace management with security integration for v2

import crypto from "crypto";
import Docker from "dockerode";
import * as tar from "tar-stream";
import { createLogger } from "../observability/logger";

const logger = createLogger("docker");

// ── Docker socket detection ───────────────────────────────────────────────

const DOCKER_SOCKET =
  process.env.DOCKER_HOST?.replace("unix://", "") ||
  (require("fs").existsSync("/var/run/docker.sock")
    ? "/var/run/docker.sock"
    : `${process.env.HOME}/.colima/default/docker.sock`);

const docker = new Docker({ socketPath: DOCKER_SOCKET });
const WORKSPACE_IMAGE = process.env.WORKSPACE_IMAGE || "devfactory-workspace:latest";
const NETWORK = process.env.DOCKER_NETWORK || "devfactory-net";
const CONTAINER_PREFIX = "devfactory-v2-ws-";
const TRAEFIK_ENTRYPOINT_PORT = "8090";

// ── Resource limits ───────────────────────────────────────────────────────

const RESOURCE_LIMITS = {
  Memory: 2 * 1024 * 1024 * 1024,  // 2GB
  NanoCpus: 2e9,                    // 2 CPUs
  PidsLimit: 256,                   // 256 PIDs
};

// ── Path validation ───────────────────────────────────────────────────────

function validateWorkspacePath(filePath: string): void {
  const normalized = filePath.replace(/\/+/g, "/");

  if (!normalized.startsWith("/workspace")) {
    throw new Error(
      `Path validation failed: "${filePath}" must start with /workspace. ` +
      "All file operations are restricted to the /workspace directory."
    );
  }

  // Prevent path traversal
  const resolved = require("path").resolve(normalized);
  if (!resolved.startsWith("/workspace")) {
    throw new Error(
      `Path validation failed: "${filePath}" resolves outside /workspace after normalization.`
    );
  }

  // Block access to sensitive paths even under /workspace
  const BLOCKED_PATTERNS = [
    /\/\.\.+\//,                 // Double-dot traversal
    /\/\.git\/config$/,          // Git config (may have credentials)
    /\/\.env\.production$/,      // Production env files
  ];

  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(normalized)) {
      throw new Error(`Path validation failed: "${filePath}" matches a blocked pattern.`);
    }
  }
}

// ── Types ─────────────────────────────────────────────────────────────────

export interface WorkspaceInfo {
  containerId: string;
  containerName: string;
  previewUrl: string;
  terminalUrl: string;
  ttydPass: string;
}

export interface ContainerHealthStatus {
  running: boolean;
  state?: string;
  health?: string;
  memoryUsageMB?: number;
  cpuPercent?: number;
  pids?: number;
  startedAt?: string;
  uptime?: number;
}

// ── Container health check ────────────────────────────────────────────────

export async function checkContainerHealth(
  containerName: string
): Promise<ContainerHealthStatus> {
  try {
    const container = docker.getContainer(containerName);
    const info = await container.inspect();

    const running = info.State?.Running ?? false;
    const result: ContainerHealthStatus = {
      running,
      state: info.State?.Status,
      health: info.State?.Health?.Status,
      startedAt: info.State?.StartedAt,
    };

    if (running && info.State?.StartedAt) {
      result.uptime = Date.now() - new Date(info.State.StartedAt).getTime();
    }

    // Get resource usage stats if running
    if (running) {
      try {
        const stats = await container.stats({ stream: false });
        if (stats.memory_stats?.usage) {
          result.memoryUsageMB = Math.round(stats.memory_stats.usage / 1024 / 1024);
        }
        if (stats.cpu_stats?.cpu_usage?.total_usage && stats.precpu_stats?.cpu_usage?.total_usage) {
          const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
          const systemDelta = (stats.cpu_stats.system_cpu_usage || 0) - (stats.precpu_stats.system_cpu_usage || 0);
          if (systemDelta > 0) {
            const numCpus = stats.cpu_stats.online_cpus || 1;
            result.cpuPercent = Math.round((cpuDelta / systemDelta) * numCpus * 100);
          }
        }
        if (stats.pids_stats?.current) {
          result.pids = stats.pids_stats.current;
        }
      } catch {
        // Stats may fail, non-critical
      }
    }

    return result;
  } catch (e: any) {
    if (e.statusCode === 404) {
      return { running: false, state: "not_found" };
    }
    throw e;
  }
}

// ── Workspace lifecycle ───────────────────────────────────────────────────

export async function createWorkspace(projectId: string): Promise<WorkspaceInfo> {
  const containerName = `${CONTAINER_PREFIX}${projectId}`;

  // Remove existing container if any
  try {
    const existing = docker.getContainer(containerName);
    await existing.stop({ t: 2 }).catch(() => {});
    await existing.remove({ force: true }).catch(() => {});
  } catch {}

  // Generate terminal credentials for this workspace
  const ttydUser = "workspace";
  const ttydPass = crypto.randomBytes(24).toString("base64url").slice(0, 32);

  logger.info({ projectId, containerName, image: WORKSPACE_IMAGE }, "Creating workspace container");

  // Create container with Traefik labels for automatic routing through port 8090
  const container = await docker.createContainer({
    Image: WORKSPACE_IMAGE,
    name: containerName,
    Env: [
      `TTYD_USER=${ttydUser}`,
      `TTYD_PASS=${ttydPass}`,
    ],
    Labels: {
      "traefik.enable": "true",
      // Preview route (port 3000)
      [`traefik.http.routers.${containerName}-preview.rule`]: `Host(\`${containerName}.localhost\`)`,
      [`traefik.http.routers.${containerName}-preview.entrypoints`]: "web",
      [`traefik.http.routers.${containerName}-preview.service`]: `${containerName}-preview`,
      [`traefik.http.services.${containerName}-preview.loadbalancer.server.port`]: "3000",
      // Terminal route (port 8080) - higher priority so /ttyd matches before catch-all
      [`traefik.http.routers.${containerName}-term.rule`]:
        `Host(\`${containerName}.localhost\`) && PathPrefix(\`/ttyd\`)`,
      [`traefik.http.routers.${containerName}-term.entrypoints`]: "web",
      [`traefik.http.routers.${containerName}-term.service`]: `${containerName}-term`,
      [`traefik.http.routers.${containerName}-term.priority`]: "100",
      [`traefik.http.routers.${containerName}-term.middlewares`]: `${containerName}-strip-ttyd`,
      [`traefik.http.middlewares.${containerName}-strip-ttyd.stripprefix.prefixes`]: "/ttyd",
      [`traefik.http.middlewares.${containerName}-strip-ttyd.stripprefix.forceslash`]: "false",
      [`traefik.http.services.${containerName}-term.loadbalancer.server.port`]: "8080",
      // Metadata
      "devfactory-v2.project-id": projectId,
      "devfactory-v2.traefik-port": TRAEFIK_ENTRYPOINT_PORT,
    },
    ExposedPorts: { "3000/tcp": {}, "8080/tcp": {} },
    HostConfig: {
      NetworkMode: NETWORK,
      Memory: RESOURCE_LIMITS.Memory,
      NanoCpus: RESOURCE_LIMITS.NanoCpus,
      PidsLimit: RESOURCE_LIMITS.PidsLimit,
      // Security hardening
      ReadonlyRootfs: false,
      SecurityOpt: ["no-new-privileges"],
    },
  });

  await container.start();

  logger.info({ projectId, containerId: container.id }, "Container started, waiting for ready state");
  await waitForReady(containerName);

  const previewUrl = `http://${containerName}.localhost:${TRAEFIK_ENTRYPOINT_PORT}`;
  const terminalUrl = `http://${containerName}.localhost:${TRAEFIK_ENTRYPOINT_PORT}/ttyd`;

  logger.info({ projectId, previewUrl, terminalUrl }, "Workspace ready");

  return {
    containerId: container.id,
    containerName,
    previewUrl,
    terminalUrl,
    ttydPass,
  };
}

export async function execInWorkspace(
  containerName: string,
  command: string
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const container = docker.getContainer(containerName);

  const exec = await container.exec({
    Cmd: ["bash", "-c", command],
    AttachStdout: true,
    AttachStderr: true,
    WorkingDir: "/workspace",
  });

  return new Promise((resolve, reject) => {
    exec.start({ hijack: true, stdin: false }, (err: any, stream: any) => {
      if (err) return reject(err);

      let stdout = "";
      let stderr = "";

      const stdoutWriter = {
        write: (chunk: Buffer) => {
          stdout += chunk.toString();
          return true;
        },
      };
      const stderrWriter = {
        write: (chunk: Buffer) => {
          stderr += chunk.toString();
          return true;
        },
      };
      docker.modem.demuxStream(stream, stdoutWriter as any, stderrWriter as any);

      stream.on("end", async () => {
        try {
          const inspect = await exec.inspect();
          resolve({
            stdout: stdout.trim(),
            stderr: stderr.trim(),
            exitCode: inspect.ExitCode ?? -1,
          });
        } catch (e) {
          resolve({ stdout: stdout.trim(), stderr: stderr.trim(), exitCode: -1 });
        }
      });

      // Timeout after 120s
      setTimeout(() => {
        stream.destroy();
        resolve({
          stdout: stdout.trim(),
          stderr: stderr.trim() + "\n[TIMEOUT after 120s]",
          exitCode: -1,
        });
      }, 120000);
    });
  });
}

export async function writeFileToWorkspace(
  containerName: string,
  filePath: string,
  content: string
): Promise<void> {
  validateWorkspacePath(filePath);

  const container = docker.getContainer(containerName);

  // Ensure parent directory exists
  const dir = filePath.substring(0, filePath.lastIndexOf("/"));
  if (dir) {
    await execInWorkspace(containerName, `mkdir -p '${dir}'`);
  }

  // Use tar-stream to write file via Docker putArchive API
  const isExecutable =
    /\.(sh|py|rb|pl)$/.test(filePath) || content.startsWith("#!");
  const pack = tar.pack();
  pack.entry(
    { name: filePath.startsWith("/") ? filePath.slice(1) : filePath, mode: isExecutable ? 0o755 : 0o644 },
    content
  );
  pack.finalize();

  await container.putArchive(pack, { path: "/" });
}

export async function readFileFromWorkspace(
  containerName: string,
  filePath: string
): Promise<string> {
  validateWorkspacePath(filePath);

  const result = await execInWorkspace(containerName, `cat '${filePath}'`);
  if (result.exitCode !== 0) {
    throw new Error(`File not found: ${filePath} - ${result.stderr}`);
  }
  return result.stdout;
}

export async function listFilesInWorkspace(
  containerName: string,
  dirPath: string = "/workspace"
): Promise<string> {
  validateWorkspacePath(dirPath);

  const result = await execInWorkspace(
    containerName,
    `find '${dirPath}' -maxdepth 3 -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/.devfactory/*' | sort | head -200`
  );
  return result.stdout;
}

export async function destroyWorkspace(containerName: string): Promise<void> {
  try {
    const container = docker.getContainer(containerName);
    await container.stop({ t: 5 }).catch(() => {});
    await container.remove({ force: true });
    logger.info({ containerName }, "Workspace destroyed");
  } catch (e: any) {
    if (e.statusCode !== 404) throw e;
  }
}

export async function getWorkspaceStatus(
  containerName: string
): Promise<{ running: boolean; state?: string }> {
  try {
    const container = docker.getContainer(containerName);
    const info = await container.inspect();
    return {
      running: info.State?.Running ?? false,
      state: info.State?.Status,
    };
  } catch (e: any) {
    if (e.statusCode === 404) return { running: false, state: "not_found" };
    throw e;
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────

async function waitForReady(containerName: string, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const result = await execInWorkspace(containerName, "cat /workspace/.devfactory/status");
      if (result.stdout.includes("ready")) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  // If status check times out, container might still be usable
  logger.warn({ containerName }, "Workspace ready check timed out, proceeding anyway");
}

// ── Terminal credential retrieval ─────────────────────────────────────────

export async function getTerminalCredentials(
  containerName: string
): Promise<{ user: string; pass: string }> {
  const result = await execInWorkspace(
    containerName,
    "cat /workspace/.devfactory/ttyd-creds"
  );
  if (result.exitCode !== 0 || !result.stdout.includes(":")) {
    throw new Error("Terminal credentials not available");
  }
  const [user, ...passParts] = result.stdout.trim().split(":");
  return { user, pass: passParts.join(":") };
}

// Export for snapshot service
export { docker, validateWorkspacePath };
