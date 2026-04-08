import { test, expect } from "@playwright/test";

const API = "http://localhost:4100";

test.describe("Observability", () => {
  test("prometheus metrics are exposed", async ({ request }) => {
    const res = await request.get(`${API}/metrics`);
    expect(res.status()).toBe(200);
    const text = await res.text();
    expect(text).toContain("active_workspaces");
    expect(text).toContain("llm_call_duration_seconds");
    expect(text).toContain("security_blocks_total");
  });

  test("health endpoint reports service status", async ({ request }) => {
    const res = await request.get(`${API}/api/health`);
    const body = await res.json();
    expect(body.status).toBe("ok");
    expect(body.services.redis).toBe("ok");
    expect(body.uptime).toBeGreaterThan(0);
  });

  test("jaeger UI is accessible", async ({ request }) => {
    const res = await request.get("http://localhost:16786");
    expect(res.status()).toBe(200);
  });
});
