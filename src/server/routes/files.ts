// src/server/routes/files.ts
// List/read/write files in workspace with path validation

import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import {
  readFileFromWorkspace,
  writeFileToWorkspace,
  listFilesInWorkspace,
  validateWorkspacePath,
} from "../services/workspace";
import { createLogger } from "../observability/logger";

const router = Router();
const prisma = new PrismaClient();
const logger = createLogger("routes:files");

// ── Helper: get container name and validate org ownership ─────────────────

async function getContainerForProject(
  projectId: string,
  orgId: string
): Promise<{ containerName: string } | { error: string; status: number }> {
  const project = await prisma.project.findFirst({
    where: { id: projectId, orgId },
    select: { containerName: true, status: true },
  });

  if (!project) {
    return { error: "Project not found", status: 404 };
  }
  if (!project.containerName) {
    return { error: "Workspace not running. Start the workspace first.", status: 400 };
  }
  if (project.status !== "running") {
    return { error: `Workspace is in "${project.status}" state, not running.`, status: 400 };
  }

  return { containerName: project.containerName };
}

// ── Helper: validate and normalize path ───────────────────────────────────

function validatePath(path: string | undefined, defaultPath = "/workspace"): { valid: boolean; normalized: string; error?: string } {
  const targetPath = path || defaultPath;

  try {
    validateWorkspacePath(targetPath);
  } catch (e: any) {
    return { valid: false, normalized: targetPath, error: e.message };
  }

  return { valid: true, normalized: targetPath };
}

// ── GET /api/files/:projectId/list?path=/workspace ────────────────────────

router.get("/:projectId/list", async (req: Request, res: Response) => {
  const orgId = req.user!.orgId;
  const containerResult = await getContainerForProject(req.params.projectId, orgId);

  if ("error" in containerResult) {
    return res.status(containerResult.status).json({ error: containerResult.error });
  }

  const pathValidation = validatePath(req.query.path as string | undefined);
  if (!pathValidation.valid) {
    return res.status(400).json({ error: pathValidation.error });
  }

  try {
    const files = await listFilesInWorkspace(containerResult.containerName, pathValidation.normalized);

    // Parse into structured list
    const fileList = files
      .split("\n")
      .filter(Boolean)
      .map((f) => {
        const name = f.split("/").pop() || f;
        const isDirectory = !name.includes(".") || f.endsWith("/");
        return {
          path: f,
          name,
          isDirectory,
        };
      });

    res.json({
      directory: pathValidation.normalized,
      files: fileList,
      count: fileList.length,
    });
  } catch (err: any) {
    logger.error({ error: err.message, projectId: req.params.projectId }, "Failed to list files");
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/files/:projectId/read?path=/workspace/src/App.tsx ────────────

router.get("/:projectId/read", async (req: Request, res: Response) => {
  const orgId = req.user!.orgId;
  const containerResult = await getContainerForProject(req.params.projectId, orgId);

  if ("error" in containerResult) {
    return res.status(containerResult.status).json({ error: containerResult.error });
  }

  const filePath = req.query.path as string;
  if (!filePath) {
    return res.status(400).json({ error: "path query parameter is required" });
  }

  const pathValidation = validatePath(filePath);
  if (!pathValidation.valid) {
    return res.status(400).json({ error: pathValidation.error });
  }

  try {
    const content = await readFileFromWorkspace(containerResult.containerName, pathValidation.normalized);
    res.json({
      path: pathValidation.normalized,
      content,
      size: content.length,
    });
  } catch (err: any) {
    logger.error({ error: err.message, path: filePath }, "Failed to read file");
    res.status(404).json({ error: err.message });
  }
});

// ── POST /api/files/:projectId/write ──────────────────────────────────────

router.post("/:projectId/write", async (req: Request, res: Response) => {
  const orgId = req.user!.orgId;
  const containerResult = await getContainerForProject(req.params.projectId, orgId);

  if ("error" in containerResult) {
    return res.status(containerResult.status).json({ error: containerResult.error });
  }

  const { path, content } = req.body;
  if (!path || typeof path !== "string") {
    return res.status(400).json({ error: "path is required and must be a string" });
  }
  if (content === undefined || content === null) {
    return res.status(400).json({ error: "content is required" });
  }

  const pathValidation = validatePath(path);
  if (!pathValidation.valid) {
    return res.status(400).json({ error: pathValidation.error });
  }

  try {
    await writeFileToWorkspace(containerResult.containerName, pathValidation.normalized, String(content));

    logger.info(
      { projectId: req.params.projectId, path: pathValidation.normalized, size: String(content).length },
      "File written via API"
    );

    res.json({
      ok: true,
      path: pathValidation.normalized,
      size: String(content).length,
    });
  } catch (err: any) {
    logger.error({ error: err.message, path }, "Failed to write file");
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/files/:projectId/tree — Get full file tree (up to depth 4) ───

router.get("/:projectId/tree", async (req: Request, res: Response) => {
  const orgId = req.user!.orgId;
  const containerResult = await getContainerForProject(req.params.projectId, orgId);

  if ("error" in containerResult) {
    return res.status(containerResult.status).json({ error: containerResult.error });
  }

  const basePath = "/workspace";
  const maxDepth = Math.min(6, Math.max(1, parseInt(req.query.depth as string) || 4));

  try {
    const { execInWorkspace } = await import("../services/docker");
    const result = await execInWorkspace(
      containerResult.containerName,
      `find '${basePath}' -maxdepth ${maxDepth} -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/.devfactory/*' | sort | head -500`
    );

    const paths = result.stdout.split("\n").filter(Boolean);

    // Build tree structure
    interface TreeNode {
      name: string;
      path: string;
      type: "file" | "directory";
      children?: TreeNode[];
    }

    const root: TreeNode = { name: "workspace", path: basePath, type: "directory", children: [] };
    const nodeMap = new Map<string, TreeNode>();
    nodeMap.set(basePath, root);

    for (const fullPath of paths) {
      if (fullPath === basePath) continue;

      const parts = fullPath.split("/");
      const name = parts[parts.length - 1];
      const parentPath = parts.slice(0, -1).join("/");
      const isDir = !name.includes(".");

      const node: TreeNode = {
        name,
        path: fullPath,
        type: isDir ? "directory" : "file",
        ...(isDir ? { children: [] } : {}),
      };

      nodeMap.set(fullPath, node);
      const parent = nodeMap.get(parentPath);
      if (parent?.children) {
        parent.children.push(node);
      }
    }

    res.json({ tree: root, totalFiles: paths.length });
  } catch (err: any) {
    logger.error({ error: err.message }, "Failed to build file tree");
    res.status(500).json({ error: err.message });
  }
});

export default router;
