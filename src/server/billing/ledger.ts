import { PrismaClient, Prisma } from "@prisma/client";

const prisma = new PrismaClient();

export interface Reservation {
  id: string;
  orgId: string;
  amount: number;
}

// Reserve credits before an LLM call (optimistic lock)
export async function reserveCredits(orgId: string, estimatedMax: number): Promise<Reservation> {
  const id = crypto.randomUUID();

  // Atomic decrement with balance check
  const org = await prisma.organization.update({
    where: { id: orgId },
    data: {
      creditBalance: { decrement: estimatedMax },
    },
  });

  if (Number(org.creditBalance) < 0) {
    // Rollback — insufficient credits
    await prisma.organization.update({
      where: { id: orgId },
      data: { creditBalance: { increment: estimatedMax } },
    });
    throw new Error("Insufficient credits");
  }

  return { id, orgId, amount: estimatedMax };
}

// Finalize after LLM call completes — debit actual amount, refund difference
export async function finalizeCredits(
  reservation: Reservation,
  actualCost: number,
  metadata: {
    userId: string;
    projectId?: string;
    eventType: string;
    model?: string;
    tokensIn?: number;
    tokensOut?: number;
  }
): Promise<void> {
  const refund = reservation.amount - actualCost;

  await prisma.$transaction(async (tx) => {
    // Refund the difference
    if (refund > 0) {
      await tx.organization.update({
        where: { id: reservation.orgId },
        data: { creditBalance: { increment: refund } },
      });
    }

    // Get current balance for ledger entry
    const org = await tx.organization.findUniqueOrThrow({ where: { id: reservation.orgId } });

    // Create usage event
    const usageEvent = await tx.usageEvent.create({
      data: {
        orgId: reservation.orgId,
        userId: metadata.userId,
        projectId: metadata.projectId,
        eventType: metadata.eventType,
        creditsUsed: actualCost,
        metadata: {
          model: metadata.model,
          tokensIn: metadata.tokensIn,
          tokensOut: metadata.tokensOut,
          reservationId: reservation.id,
        },
      },
    });

    // Create ledger entry
    await tx.creditLedgerEntry.create({
      data: {
        orgId: reservation.orgId,
        amount: -actualCost,
        balanceAfter: Number(org.creditBalance),
        source: "usage",
        referenceId: usageEvent.id,
        description: `${metadata.eventType}: ${metadata.model || "unknown"}`,
      },
    });
  });
}

// Release reservation without charging (on error)
export async function releaseReservation(reservation: Reservation): Promise<void> {
  await prisma.organization.update({
    where: { id: reservation.orgId },
    data: { creditBalance: { increment: reservation.amount } },
  });
}

// Get current balance
export async function getBalance(orgId: string): Promise<{ credits: number; plan: string }> {
  const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId } });
  return { credits: Number(org.creditBalance), plan: org.plan };
}

// Get usage for a time period
export async function getUsage(orgId: string, since: Date): Promise<{
  totalCredits: number;
  byType: Record<string, number>;
  byModel: Record<string, number>;
}> {
  const events = await prisma.usageEvent.findMany({
    where: { orgId, createdAt: { gte: since } },
  });

  const byType: Record<string, number> = {};
  const byModel: Record<string, number> = {};
  let totalCredits = 0;

  for (const e of events) {
    const credits = Number(e.creditsUsed);
    totalCredits += credits;
    byType[e.eventType] = (byType[e.eventType] || 0) + credits;
    const model = (e.metadata as any)?.model || "unknown";
    byModel[model] = (byModel[model] || 0) + credits;
  }

  return { totalCredits, byType, byModel };
}
