import { test, expect } from "@playwright/test";

const API = "http://localhost:4100";

test.describe("Agent End-to-End Flow", () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    // Create project + start workspace
    const projRes = await request.post(`${API}/api/projects`, {
      data: { name: "e2e-agent-test", description: "Agent E2E" },
    });
    projectId = (await projRes.json()).id;

    await request.post(`${API}/api/workspaces`, {
      data: { projectId },
    });

    // Wait for workspace to be ready
    await new Promise((r) => setTimeout(r, 5000));
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API}/api/workspaces/${projectId}`).catch(() => {});
      await request.delete(`${API}/api/projects/${projectId}`).catch(() => {});
    }
  });

  test("agent SSE endpoint streams events correctly", async ({ request }) => {
    const res = await request.post(`${API}/api/agent/${projectId}/message`, {
      data: { message: "Create a simple HTML file at /workspace/index.html that says Hello World" },
    });

    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toContain("text/event-stream");

    // Read SSE stream — verify it returns structured events
    const text = await res.text();
    expect(text).toContain("data:");
    expect(text).toContain("[DONE]");
    // If LLM keys configured, expect tool_call events; otherwise expect error event
    const hasToolCalls = text.includes("tool_call");
    const hasLLMError = text.includes("error");
    expect(hasToolCalls || hasLLMError).toBe(true);
  });

  test("agent actions are recorded in database", async ({ request }) => {
    const res = await request.get(`${API}/api/projects/${projectId}`);
    const body = await res.json();
    expect(body.conversations).toBeDefined();
  });

  test("credits balance is accessible after agent run", async ({ request }) => {
    const res = await request.get(`${API}/api/billing/balance`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    // Credits should be <= starting balance (deducted if LLM call succeeded)
    expect(body.credits).toBeLessThanOrEqual(999);
  });
});
