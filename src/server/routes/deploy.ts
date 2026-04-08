import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { deployProject } from "../deploy/deployer";

const router = Router();
const prisma = new PrismaClient();

// POST /api/deploy/:projectId
router.post("/:projectId", async (req, res) => {
  try {
    const result = await deployProject(req.params.projectId, req.user!.id);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/deploy/:projectId/deployments
router.get("/:projectId/deployments", async (req, res) => {
  const deployments = await prisma.deployment.findMany({
    where: { projectId: req.params.projectId },
    orderBy: { createdAt: "desc" },
    take: 20,
  });
  res.json(deployments);
});

// GET /api/deploy/deployment/:id
router.get("/deployment/:id", async (req, res) => {
  const deployment = await prisma.deployment.findUnique({ where: { id: req.params.id } });
  if (!deployment) return res.status(404).json({ error: "Not found" });
  res.json(deployment);
});

export default router;
