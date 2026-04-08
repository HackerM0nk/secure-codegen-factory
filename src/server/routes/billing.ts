import { Router } from "express";
import { authMiddleware } from "../middleware/auth";
import { getBalance, getUsage } from "../billing/ledger";

const router = Router();

// GET /api/billing/balance
router.get("/balance", authMiddleware(), async (req, res) => {
  try {
    const balance = await getBalance(req.user!.orgId);
    res.json(balance);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/billing/usage?period=current_month|last_30d|all
router.get("/usage", authMiddleware(), async (req, res) => {
  const period = (req.query.period as string) || "current_month";
  let since: Date;

  switch (period) {
    case "current_month":
      since = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
      break;
    case "last_30d":
      since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      break;
    default:
      since = new Date(0);
  }

  try {
    const usage = await getUsage(req.user!.orgId, since);
    res.json({ period, since: since.toISOString(), ...usage });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
