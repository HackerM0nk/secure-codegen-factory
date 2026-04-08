import { test, expect } from "@playwright/test";

const API = "http://localhost:4100";

test.describe("Workspace Lifecycle", () => {
  let projectId: string;

  test.beforeAll(async ({ request }) => {
    // Create a test project
    const res = await request.post(`${API}/api/projects`, {
      data: { name: "e2e-test-project", description: "E2E test" },
    });
    const body = await res.json();
    projectId = body.id;
  });

  test.afterAll(async ({ request }) => {
    // Cleanup
    if (projectId) {
      await request.delete(`${API}/api/workspaces/${projectId}`).catch(() => {});
      await request.delete(`${API}/api/projects/${projectId}`).catch(() => {});
    }
  });

  test("create and start workspace", async ({ request }) => {
    const res = await request.post(`${API}/api/workspaces`, {
      data: { projectId },
    });
    expect([200, 201]).toContain(res.status());
    const body = await res.json();
    expect(body.containerName).toContain(projectId.substring(0, 8));
    expect(body.previewUrl).toBeTruthy();
  });

  test("workspace status is running", async ({ request }) => {
    const res = await request.get(`${API}/api/projects/${projectId}`);
    const body = await res.json();
    expect(body.status).toBe("running");
  });

  test("can list files in workspace", async ({ request }) => {
    const res = await request.get(`${API}/api/files/${projectId}/list`);
    expect(res.status()).toBe(200);
  });

  test("can stop workspace", async ({ request }) => {
    const res = await request.delete(`${API}/api/workspaces/${projectId}`);
    expect(res.status()).toBe(200);
  });
});
