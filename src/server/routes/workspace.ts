// src/server/routes/workspace.ts
// Start/stop workspace with concurrent limit enforcement

import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import {
  createWorkspace,
  destroyWorkspace,
  getWorkspaceStatus,
  checkContainerHealth,
  getTerminalCredentials,
  saveSnapshot,
  restoreSnapshot,
} from "../services/workspace";
import { runPreviewGate } from "../deploy/pre-deploy-gate";
import {
  checkConcurrentLimit,
  trackWorkspace,
  untrackWorkspace,
} from "../middleware/rate-limiter";
import { EventBus } from "../events/event-bus";
import { EVENT_TYPES } from "../events/events";
import { createLogger } from "../observability/logger";
import { metrics } from "../observability/metrics";

const router = Router();
const prisma = new PrismaClient();
const logger = createLogger("routes:workspace");

// ── POST /api/workspaces — Create and start a workspace ──────────────────

router.post("/", async (req: Request, res: Response) => {
  const { projectId } = req.body;
  const userId = req.user!.id;
  const plan = req.user!.plan;

  if (!projectId) {
    return res.status(400).json({ error: "projectId is required" });
  }

  try {
    const project = await prisma.project.findFirst({
      where: { id: projectId, orgId: req.user!.orgId },
    });
    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    // If already running, return existing info
    if (project.status === "running" && project.containerName) {
      const status = await getWorkspaceStatus(project.containerName);
      if (status.running) {
        return res.json({
          containerId: project.containerId,
          containerName: project.containerName,
          previewUrl: project.previewUrl,
          status: "running",
        });
      }
    }

    // Check concurrent workspace limit based on plan
    const concurrencyCheck = await checkConcurrentLimit(userId, plan);
    if (!concurrencyCheck.allowed) {
      return res.status(429).json({
        error: "Concurrent workspace limit reached",
        current: concurrencyCheck.current,
        max: concurrencyCheck.max,
        plan,
        message: `Your ${plan} plan allows ${concurrencyCheck.max} concurrent workspace(s). Stop an existing workspace first.`,
      });
    }

    // Set project status to starting
    await prisma.project.update({
      where: { id: projectId },
      data: { status: "starting" },
    });

    // Create the workspace container
    const workspaceCreateStart = Date.now();
    const info = await createWorkspace(projectId);
    metrics.workspaceCreationDuration.observe((Date.now() - workspaceCreateStart) / 1000);
    metrics.activeWorkspaces.inc();

    // Track for concurrent limits
    await trackWorkspace(userId, projectId);

    // Restore snapshot if available
    if (project.snapshotKey) {
      try {
        const restoreResult = await restoreSnapshot(
          info.containerName,
          project.snapshotKey,
          project.snapshotHash || undefined
        );

        // Emit restore event
        const eventBus: EventBus | undefined = req.app.get("eventBus");
        if (eventBus) {
          await eventBus.emit("workspace", EVENT_TYPES.WORKSPACE_SNAPSHOT_RESTORED, {
            projectId,
            snapshotKey: project.snapshotKey,
            durationMs: restoreResult.durationMs,
          });
        }
      } catch (e: any) {
        logger.warn(
          { projectId, snapshotKey: project.snapshotKey, error: e.message },
          "Failed to restore snapshot"
        );
      }
    }

    // Run preview gate on restored snapshots before exposing preview URL.
    // Fresh workspaces (no snapshot) skip this — there's no code to scan yet.
    let previewUrl: string | null = info.previewUrl;
    if (project.snapshotKey) {
      try {
        const gate = await runPreviewGate(info.containerName);
        if (!gate.passed) {
          logger.warn(
            { projectId, blockReasons: gate.blockReasons },
            "Preview gate blocked — preview URL withheld until code is safe"
          );
          previewUrl = null;
        }
      } catch (e: any) {
        logger.warn({ projectId, error: e.message }, "Preview gate check failed — allowing preview");
      }
    }

    // Update project with container info
    await prisma.project.update({
      where: { id: projectId },
      data: {
        containerId: info.containerId,
        containerName: info.containerName,
        previewUrl,
        status: "running",
      },
    });

    // Emit workspace created event
    const eventBus: EventBus | undefined = req.app.get("eventBus");
    if (eventBus) {
      await eventBus.emit("workspace", EVENT_TYPES.WORKSPACE_CREATED, {
        projectId,
        containerId: info.containerId,
        containerName: info.containerName,
      });
    }

    logger.info({ projectId, containerName: info.containerName }, "Workspace started");
    res.status(201).json({ ...info, previewUrl });
  } catch (err: any) {
    logger.error({ projectId, error: err.message }, "Workspace creation failed");

    // Reset project status on failure
    if (projectId) {
      await prisma.project
        .update({ where: { id: projectId }, data: { status: "error" } })
        .catch(() => {});
    }

    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/workspaces/:projectId — Stop and destroy workspace ────────

router.delete("/:projectId", async (req: Request, res: Response) => {
  const projectId = req.params.projectId;
  const userId = req.user!.id;

  try {
    const project = await prisma.project.findFirst({
      where: { id: projectId, orgId: req.user!.orgId },
    });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    if (project.containerName) {
      // Save snapshot before destroying
      try {
        const snapshotResult = await saveSnapshot(project.containerName, projectId);
        await prisma.project.update({
          where: { id: projectId },
          data: {
            snapshotKey: snapshotResult.snapshotKey,
            snapshotHash: snapshotResult.snapshotHash,
          },
        });

        // Emit snapshot saved event
        const eventBus: EventBus | undefined = req.app.get("eventBus");
        if (eventBus) {
          await eventBus.emit("workspace", EVENT_TYPES.WORKSPACE_SNAPSHOT_SAVED, {
            projectId,
            snapshotKey: snapshotResult.snapshotKey,
            sizeBytes: snapshotResult.sizeBytes,
          });
        }
      } catch (e: any) {
        logger.warn(
          { projectId, containerName: project.containerName, error: e.message },
          "Failed to save snapshot before destroy"
        );
      }

      // Destroy the container
      await destroyWorkspace(project.containerName);
      metrics.activeWorkspaces.dec();

      // Emit workspace destroyed event
      const eventBus: EventBus | undefined = req.app.get("eventBus");
      if (eventBus) {
        await eventBus.emit("workspace", EVENT_TYPES.WORKSPACE_DESTROYED, {
          projectId,
          containerId: project.containerId || "",
        });
      }
    }

    // Untrack concurrent usage
    await untrackWorkspace(userId, projectId);

    // Update project status
    await prisma.project.update({
      where: { id: projectId },
      data: {
        containerId: null,
        containerName: null,
        previewUrl: null,
        status: "stopped",
      },
    });

    logger.info({ projectId }, "Workspace stopped and destroyed");
    res.json({ ok: true });
  } catch (err: any) {
    logger.error({ projectId, error: err.message }, "Failed to destroy workspace");
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/workspaces/:projectId/status — Get workspace status ─────────

router.get("/:projectId/status", async (req: Request, res: Response) => {
  const projectId = req.params.projectId;

  try {
    const project = await prisma.project.findFirst({
      where: { id: projectId, orgId: req.user!.orgId },
    });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    if (!project.containerName) {
      return res.json({
        running: false,
        status: project.status || "stopped",
        projectId,
      });
    }

    const status = await getWorkspaceStatus(project.containerName);
    res.json({
      ...status,
      projectStatus: project.status,
      containerName: project.containerName,
      previewUrl: project.previewUrl,
      projectId,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/workspaces/:projectId/health — Detailed container health ─────

router.get("/:projectId/health", async (req: Request, res: Response) => {
  const projectId = req.params.projectId;

  try {
    const project = await prisma.project.findFirst({
      where: { id: projectId, orgId: req.user!.orgId },
    });

    if (!project?.containerName) {
      return res.status(404).json({ error: "No running workspace for this project" });
    }

    const health = await checkContainerHealth(project.containerName);
    res.json({
      projectId,
      containerName: project.containerName,
      ...health,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/workspaces/:projectId/terminal-creds — Retrieve ttyd auth ────

router.get("/:projectId/terminal-creds", async (req: Request, res: Response) => {
  const projectId = req.params.projectId;

  try {
    const project = await prisma.project.findFirst({
      where: { id: projectId, orgId: req.user!.orgId },
    });

    if (!project?.containerName) {
      return res.status(404).json({ error: "No running workspace for this project" });
    }

    const status = await getWorkspaceStatus(project.containerName);
    if (!status.running) {
      return res.status(404).json({ error: "Workspace is not running" });
    }

    const creds = await getTerminalCredentials(project.containerName);
    res.json(creds);
  } catch (err: any) {
    logger.error({ projectId, error: err.message }, "Failed to retrieve terminal credentials");
    res.status(500).json({ error: "Failed to retrieve terminal credentials" });
  }
});

export default router;
