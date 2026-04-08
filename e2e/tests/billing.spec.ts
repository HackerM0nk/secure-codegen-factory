import { test, expect } from "@playwright/test";

const API = "http://localhost:4100";

test.describe("Billing & Credits", () => {
  test("can fetch credit balance", async ({ request }) => {
    const res = await request.get(`${API}/api/billing/balance`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.credits).toBeGreaterThan(0);
    expect(body.plan).toBeTruthy();
  });

  test("can fetch usage report", async ({ request }) => {
    const res = await request.get(`${API}/api/billing/usage?period=current_month`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.period).toBe("current_month");
    expect(typeof body.totalCredits).toBe("number");
  });
});
