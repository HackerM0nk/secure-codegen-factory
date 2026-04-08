import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { generateDevToken, authMiddleware } from "../middleware/auth";

const router = Router();
const prisma = new PrismaClient();

// POST /api/auth/dev-login — Dev-only endpoint for getting a JWT
router.post("/dev-login", async (req, res) => {
  if (process.env.NODE_ENV !== "development") {
    return res.status(404).json({ error: "Not found" });
  }

  const user = await prisma.user.findUnique({
    where: { email: "dev@local.dev" },
    include: { memberships: { include: { org: true }, take: 1 } },
  });

  if (!user) return res.status(404).json({ error: "Run prisma db seed first" });

  const token = generateDevToken(user.id);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      orgId: user.memberships[0]?.orgId,
      role: user.memberships[0]?.role,
      plan: user.memberships[0]?.org.plan,
    },
  });
});

// GET /api/auth/me
router.get("/me", authMiddleware(), async (req, res) => {
  res.json(req.user);
});

// GET /api/auth/keycloak-config — Frontend uses this to configure OIDC
router.get("/keycloak-config", (_, res) => {
  res.json({
    url: process.env.KEYCLOAK_URL || "http://localhost:8280",
    realm: process.env.KEYCLOAK_REALM || "devfactory",
    clientId: "devfactory-web",
  });
});

export default router;
