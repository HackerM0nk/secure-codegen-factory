// src/server/routes/project.ts
// CRUD for projects with org scoping and pagination

import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { createLogger } from "../observability/logger";

const router = Router();
const prisma = new PrismaClient();
const logger = createLogger("routes:project");

// ── GET /api/projects — List projects with pagination ─────────────────────

router.get("/", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
    const skip = (page - 1) * limit;
    const search = (req.query.search as string) || "";
    const status = req.query.status as string | undefined;
    const sortBy = (req.query.sortBy as string) || "updatedAt";
    const sortOrder = (req.query.sortOrder as string) === "asc" ? "asc" : "desc";

    // Build where clause
    const where: any = { orgId };
    if (search) {
      where.OR = [
        { name: { contains: search, mode: "insensitive" } },
        { description: { contains: search, mode: "insensitive" } },
        { slug: { contains: search, mode: "insensitive" } },
      ];
    }
    if (status) {
      where.status = status;
    }

    // Build orderBy
    const validSortFields = ["updatedAt", "createdAt", "name", "status"];
    const orderField = validSortFields.includes(sortBy) ? sortBy : "updatedAt";

    const [projects, total] = await Promise.all([
      prisma.project.findMany({
        where,
        orderBy: { [orderField]: sortOrder },
        skip,
        take: limit,
        select: {
          id: true,
          name: true,
          slug: true,
          description: true,
          visibility: true,
          status: true,
          previewUrl: true,
          techStack: true,
          creatorId: true,
          createdAt: true,
          updatedAt: true,
        },
      }),
      prisma.project.count({ where }),
    ]);

    res.json({
      data: projects,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasMore: skip + limit < total,
      },
    });
  } catch (err: any) {
    logger.error({ error: err.message }, "Failed to list projects");
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/projects/:id — Get single project ───────────────────────────

router.get("/:id", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const project = await prisma.project.findFirst({
      where: { id: req.params.id, orgId },
      include: {
        conversations: {
          orderBy: { createdAt: "desc" },
          take: 5,
          include: {
            messages: {
              orderBy: { createdAt: "desc" },
              take: 1,
              select: { id: true, role: true, createdAt: true },
            },
          },
        },
        template: {
          select: { id: true, name: true, category: true },
        },
      },
    });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    res.json(project);
  } catch (err: any) {
    logger.error({ error: err.message, projectId: req.params.id }, "Failed to get project");
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/projects — Create project ──────────────────────────────────

router.post("/", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const userId = req.user!.id;
    const { name, description, visibility, templateId, techStack } = req.body;

    if (!name || typeof name !== "string" || name.trim().length === 0) {
      return res.status(400).json({ error: "name is required" });
    }

    // Generate slug from name
    const baseSlug = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .substring(0, 60);

    // Ensure unique slug within org
    let slug = baseSlug;
    let attempt = 0;
    while (true) {
      const existing = await prisma.project.findFirst({
        where: { orgId, slug },
      });
      if (!existing) break;
      attempt++;
      slug = `${baseSlug}-${attempt}`;
    }

    const project = await prisma.project.create({
      data: {
        orgId,
        creatorId: userId,
        name: name.trim(),
        slug,
        description: description || null,
        visibility: visibility || "private",
        templateId: templateId || null,
        techStack: techStack || null,
      },
    });

    logger.info({ projectId: project.id, orgId, slug }, "Project created");
    res.status(201).json(project);
  } catch (err: any) {
    logger.error({ error: err.message }, "Failed to create project");
    res.status(500).json({ error: err.message });
  }
});

// ── PATCH /api/projects/:id — Update project ─────────────────────────────

router.patch("/:id", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const projectId = req.params.id;

    // Verify project belongs to org
    const existing = await prisma.project.findFirst({
      where: { id: projectId, orgId },
    });
    if (!existing) {
      return res.status(404).json({ error: "Project not found" });
    }

    const allowedFields = ["name", "description", "visibility", "techStack"];
    const updateData: Record<string, any> = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updateData[field] = req.body[field];
      }
    }

    // Regenerate slug if name changed
    if (updateData.name && updateData.name !== existing.name) {
      const baseSlug = updateData.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .substring(0, 60);

      let slug = baseSlug;
      let attempt = 0;
      while (true) {
        const dup = await prisma.project.findFirst({
          where: { orgId, slug, NOT: { id: projectId } },
        });
        if (!dup) break;
        attempt++;
        slug = `${baseSlug}-${attempt}`;
      }
      updateData.slug = slug;
    }

    const project = await prisma.project.update({
      where: { id: projectId },
      data: updateData,
    });

    logger.info({ projectId, orgId, updated: Object.keys(updateData) }, "Project updated");
    res.json(project);
  } catch (err: any) {
    logger.error({ error: err.message, projectId: req.params.id }, "Failed to update project");
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/projects/:id — Delete project ─────────────────────────────

router.delete("/:id", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const projectId = req.params.id;

    // Verify project belongs to org
    const existing = await prisma.project.findFirst({
      where: { id: projectId, orgId },
    });
    if (!existing) {
      return res.status(404).json({ error: "Project not found" });
    }

    // Don't allow deletion if workspace is running
    if (existing.status === "running") {
      return res.status(409).json({
        error: "Cannot delete project with a running workspace. Stop the workspace first.",
      });
    }

    await prisma.project.delete({ where: { id: projectId } });

    logger.info({ projectId, orgId }, "Project deleted");
    res.json({ ok: true });
  } catch (err: any) {
    logger.error({ error: err.message, projectId: req.params.id }, "Failed to delete project");
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/projects/:id/fork — Fork a project ─────────────────────────

router.post("/:id/fork", async (req: Request, res: Response) => {
  try {
    const orgId = req.user!.orgId;
    const userId = req.user!.id;
    const sourceId = req.params.id;

    const source = await prisma.project.findUnique({ where: { id: sourceId } });
    if (!source) {
      return res.status(404).json({ error: "Source project not found" });
    }

    // Only allow forking public/internal projects from other orgs
    if (source.orgId !== orgId && source.visibility === "private") {
      return res.status(403).json({ error: "Cannot fork a private project" });
    }

    const forkName = req.body.name || `${source.name} (fork)`;
    const baseSlug = forkName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .substring(0, 60);

    let slug = baseSlug;
    let attempt = 0;
    while (true) {
      const dup = await prisma.project.findFirst({ where: { orgId, slug } });
      if (!dup) break;
      attempt++;
      slug = `${baseSlug}-${attempt}`;
    }

    const fork = await prisma.project.create({
      data: {
        orgId,
        creatorId: userId,
        name: forkName,
        slug,
        description: source.description,
        visibility: "private",
        forkedFromId: sourceId,
        techStack: source.techStack as any,
        snapshotKey: source.snapshotKey,
        snapshotHash: source.snapshotHash,
      },
    });

    logger.info({ forkId: fork.id, sourceId, orgId }, "Project forked");
    res.status(201).json(fork);
  } catch (err: any) {
    logger.error({ error: err.message }, "Failed to fork project");
    res.status(500).json({ error: err.message });
  }
});

export default router;
