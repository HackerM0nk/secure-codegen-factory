import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 120_000, // 2 min per test (agent builds take time)
  retries: 1,
  workers: 1, // Sequential — shared Docker resources
  use: {
    baseURL: "http://localhost:4100",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
  webServer: [
    {
      command: "docker compose up -d && npx prisma db push && npx prisma db seed && npm run dev",
      url: "http://localhost:4100/api/health",
      reuseExistingServer: true,
      timeout: 60_000,
    },
  ],
});
