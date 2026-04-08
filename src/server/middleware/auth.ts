import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || "dev-jwt-secret-change-in-production";

export interface AuthUser {
  id: string;
  email: string;
  orgId: string;
  orgSlug: string;
  role: string;
  plan: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// Keycloak OIDC token verification
// In production: verify against Keycloak's JWKS endpoint with RS256
// For local dev: verify signature using shared JWT_SECRET
async function verifyKeycloakToken(token: string): Promise<{ sub: string; email: string; realm_access?: { roles: string[] } } | null> {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    if (!decoded || !decoded.sub || !decoded.email) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function authMiddleware(required = true) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      if (required) return res.status(401).json({ error: "Authentication required. Use POST /api/auth/dev-login to get a token." });
      return next();
    }

    const token = authHeader.slice(7);

    // Try Keycloak token first
    const keycloakPayload = await verifyKeycloakToken(token);
    if (keycloakPayload) {
      let user = await prisma.user.findUnique({
        where: { keycloakId: keycloakPayload.sub },
        include: { memberships: { include: { org: true }, take: 1 } },
      });

      // Auto-provision user on first login
      if (!user) {
        const defaultOrg = await prisma.organization.findFirst({ where: { slug: "default" } });
        user = await prisma.user.create({
          data: {
            email: keycloakPayload.email,
            keycloakId: keycloakPayload.sub,
            memberships: defaultOrg
              ? { create: { orgId: defaultOrg.id, role: "member" } }
              : undefined,
          },
          include: { memberships: { include: { org: true }, take: 1 } },
        });
      }

      if (user.memberships[0]) {
        req.user = {
          id: user.id,
          email: user.email,
          orgId: user.memberships[0].orgId,
          orgSlug: user.memberships[0].org.slug,
          role: user.memberships[0].role,
          plan: user.memberships[0].org.plan,
        };
      }
      return next();
    }

    // Try simple JWT (for dev/testing)
    try {
      const payload = jwt.verify(token, JWT_SECRET) as any;
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        include: { memberships: { include: { org: true }, take: 1 } },
      });

      if (user && user.memberships[0]) {
        req.user = {
          id: user.id,
          email: user.email,
          orgId: user.memberships[0].orgId,
          orgSlug: user.memberships[0].org.slug,
          role: user.memberships[0].role,
          plan: user.memberships[0].org.plan,
        };
      }
      return next();
    } catch {
      if (required) return res.status(401).json({ error: "Invalid token" });
      return next();
    }
  };
}

// RBAC middleware — role hierarchy: owner > admin > member > viewer
const ROLE_HIERARCHY: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    const userLevel = ROLE_HIERARCHY[req.user.role] ?? -1;
    const minRequired = Math.min(...roles.map((r) => ROLE_HIERARCHY[r] ?? 99));
    if (userLevel < minRequired) {
      return res.status(403).json({ error: "Insufficient permissions", required: roles });
    }
    next();
  };
}

// Generate dev JWT (for testing)
export function generateDevToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
}
