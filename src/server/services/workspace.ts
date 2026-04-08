// src/server/services/workspace.ts
// Workspace facade — routes to Docker or K8s based on WORKSPACE_RUNTIME env var

import * as docker from "./docker";

const RUNTIME = process.env.WORKSPACE_RUNTIME || "docker";

async function getK8s() {
  return import("./k8s-workspace");
}

export async function createWorkspace(projectId: string, snapshotKey?: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.createWorkspace(projectId, snapshotKey);
  }
  return docker.createWorkspace(projectId);
}

export async function execInWorkspace(containerName: string, command: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.execInWorkspace(containerName, command);
  }
  return docker.execInWorkspace(containerName, command);
}

export async function writeFileToWorkspace(containerName: string, filePath: string, content: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.writeFileToWorkspace(containerName, filePath, content);
  }
  return docker.writeFileToWorkspace(containerName, filePath, content);
}

export async function readFileFromWorkspace(containerName: string, filePath: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.readFileFromWorkspace(containerName, filePath);
  }
  return docker.readFileFromWorkspace(containerName, filePath);
}

export async function listFilesInWorkspace(containerName: string, dirPath?: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.listFilesInWorkspace(containerName, dirPath);
  }
  return docker.listFilesInWorkspace(containerName, dirPath);
}

export async function destroyWorkspace(containerName: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.destroyWorkspace(containerName);
  }
  return docker.destroyWorkspace(containerName);
}

export async function getWorkspaceStatus(containerName: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.getWorkspaceStatus(containerName);
  }
  return docker.getWorkspaceStatus(containerName);
}

export async function checkContainerHealth(containerName: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    return k8s.checkContainerHealth(containerName);
  }
  return docker.checkContainerHealth(containerName);
}

// ── Snapshot operations ───────────────────────────────────────────────────
// Currently Docker-specific via snapshot.ts. The K8s runtime will need its
// own implementation (e.g. kubectl cp or direct S3 streaming to pod volumes).

export { saveSnapshot, restoreSnapshot, verifySnapshot } from "./snapshot";
export type { SnapshotResult } from "./snapshot";

export async function getTerminalCredentials(containerName: string) {
  if (RUNTIME === "kubernetes") {
    const k8s = await getK8s();
    if ("getTerminalCredentials" in k8s) {
      return (k8s as any).getTerminalCredentials(containerName);
    }
  }
  return docker.getTerminalCredentials(containerName);
}

// Re-export types
export type { WorkspaceInfo, ContainerHealthStatus } from "./docker";
export { validateWorkspacePath } from "./docker";
