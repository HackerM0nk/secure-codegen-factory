import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  // Create default org
  const org = await prisma.organization.upsert({
    where: { slug: "default" },
    update: {},
    create: {
      name: "Default Organization",
      slug: "default",
      plan: "pro",
      creditBalance: 999,
    },
  });

  // Create dev user
  const user = await prisma.user.upsert({
    where: { email: "dev@local.dev" },
    update: {},
    create: {
      email: "dev@local.dev",
      name: "Dev User",
    },
  });

  // Create membership
  await prisma.orgMembership.upsert({
    where: { userId_orgId: { userId: user.id, orgId: org.id } },
    update: {},
    create: {
      userId: user.id,
      orgId: org.id,
      role: "owner",
    },
  });

  // Initial credit ledger entry
  await prisma.creditLedgerEntry.create({
    data: {
      orgId: org.id,
      amount: 999,
      balanceAfter: 999,
      source: "daily_grant",
      description: "Initial dev credits",
    },
  });

  // Sample template
  await prisma.template.upsert({
    where: { id: "template-react-vite" },
    update: {},
    create: {
      id: "template-react-vite",
      name: "React + Vite Starter",
      description: "Modern React app with Vite, TypeScript, and Tailwind CSS",
      category: "dashboard",
      techStack: { framework: "react", bundler: "vite", styling: "tailwind", language: "typescript" },
      fileSnapshot: {},
      isFeatured: true,
    },
  });

  console.log("Seeded: org=%s, user=%s", org.slug, user.email);
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
