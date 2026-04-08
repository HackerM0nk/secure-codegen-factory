// tests/e2e-security/harness.ts
// Security regression test harness.
//
// Two modes:
//   1. UNIT MODE: Tests security endpoints directly (fast, no LLM needed)
//   2. E2E MODE:  Sends prompts through full agent pipeline with uncensored LLM
//
// Usage:
//   npx tsx tests/e2e-security/harness.ts                    # Run unit tests only
//   npx tsx tests/e2e-security/harness.ts --mode=e2e         # Run E2E with agent pipeline
//   npx tsx tests/e2e-security/harness.ts --model=dolphin-mistral:7b  # Specify model
//   npx tsx tests/e2e-security/harness.ts --category=REVERSE_SHELL    # Filter by category
//   npx tsx tests/e2e-security/harness.ts --id=PI-001,RS-001          # Run specific vectors
//   npx tsx tests/e2e-security/harness.ts --report                    # Generate JSON report

import {
  ATTACK_VECTORS,
  getVectorStats,
  type AttackVector,
  type SecurityLayer,
  type ThreatCategory,
} from "./attack-vectors";

// ── Config ────────────────────────────────────────────────────────────

const API_URL = process.env.API_URL || "http://localhost:4100";
let AUTH_TOKEN = process.env.AUTH_TOKEN || "";

async function ensureAuthToken(): Promise<void> {
  if (AUTH_TOKEN) return;
  try {
    const res = await fetch(`${API_URL}/api/auth/dev-login`, { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      AUTH_TOKEN = data.token;
    }
  } catch {}
}

interface RunConfig {
  mode: "unit" | "e2e" | "both";
  model?: string;
  categories?: ThreatCategory[];
  ids?: string[];
  generateReport: boolean;
  verbose: boolean;
  apiUrl: string;
}

// ── Result types ──────────────────────────────────────────────────────

interface TestResult {
  vectorId: string;
  vectorName: string;
  category: ThreatCategory;
  severity: string;
  mode: "unit" | "e2e";
  passed: boolean;
  expectedLayers: SecurityLayer[];
  detectedByLayers: SecurityLayer[];
  missedByLayers: SecurityLayer[];
  response: any;
  durationMs: number;
  error?: string;
}

interface TestReport {
  timestamp: string;
  config: RunConfig;
  model?: string;
  summary: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    passRate: string;
    duration: string;
  };
  layerCoverage: Record<string, { tested: number; caught: number; missed: number; rate: string }>;
  categoryCoverage: Record<string, { tested: number; passed: number; failed: number }>;
  results: TestResult[];
  gaps: Array<{ vectorId: string; name: string; severity: string; missedLayers: string[] }>;
  recommendations: string[];
}

// ── ANSI colors ───────────────────────────────────────────────────────

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const NC = "\x1b[0m";

// ── HTTP helper ───────────────────────────────────────────────────────

async function apiCall(
  path: string,
  body: Record<string, any>,
  config: RunConfig
): Promise<{ status: number; data: any; durationMs: number }> {
  const url = `${config.apiUrl}${path}`;
  const start = Date.now();

  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (AUTH_TOKEN) {
      headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
    }

    const resp = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });

    const data = await resp.json().catch(() => ({}));
    return { status: resp.status, data, durationMs: Date.now() - start };
  } catch (err: any) {
    return {
      status: 0,
      data: { error: err.message },
      durationMs: Date.now() - start,
    };
  }
}

// ── JSON path resolver ────────────────────────────────────────────────

function resolveJsonPath(obj: any, path: string): any {
  const parts = path.split(".");
  let current = obj;
  for (const part of parts) {
    if (current == null) return undefined;
    current = current[part];
  }
  return current;
}

// ── Criteria evaluator ────────────────────────────────────────────────

function evaluateCriteria(
  response: any,
  criteria: AttackVector["unitPassCriteria"]
): { passed: boolean; details: string[] } {
  if (!criteria || criteria.length === 0) {
    return { passed: true, details: ["No criteria defined"] };
  }

  const details: string[] = [];
  let allPassed = true;

  for (const c of criteria) {
    const actual = resolveJsonPath(response, c.field);
    let passed = false;

    switch (c.operator) {
      case "equals":
        passed = actual === c.value;
        break;
      case "contains":
        passed = typeof actual === "string" && actual.toLowerCase().includes(String(c.value).toLowerCase());
        break;
      case "truthy":
        passed = !!actual;
        break;
      case "gte":
        passed = typeof actual === "number" && actual >= c.value;
        break;
      case "oneOf":
        passed = Array.isArray(c.value) && c.value.includes(actual);
        break;
    }

    if (!passed) allPassed = false;
    details.push(
      `${passed ? "✓" : "✗"} ${c.field} ${c.operator} ${JSON.stringify(c.value)} (actual: ${JSON.stringify(actual)})`
    );
  }

  return { passed: allPassed, details };
}

// ── Endpoint mapping ──────────────────────────────────────────────────

const ENDPOINT_MAP: Record<string, string> = {
  "test-input": "/api/security/test-input",
  "test-command": "/api/security/test-command",
  "test-package": "/api/security/test-package",
  "test-injection": "/api/security/test-injection",
  "classify-intent": "/api/security/classify-intent",
};

// ── Infer detected layers from response ───────────────────────────────

function inferDetectedLayers(
  vector: AttackVector,
  response: any,
  endpoint?: string
): SecurityLayer[] {
  const detected: SecurityLayer[] = [];

  // Input firewall
  if (response?.firewall?.blocked) {
    detected.push("input_firewall");
  }

  // Injection detector
  if (response?.blocked && endpoint === "test-injection") {
    detected.push("injection_detector");
  }
  if (response?.attacks?.length > 0) {
    detected.push("injection_detector");
  }

  // Intent classifier
  if (response?.recommendation === "BLOCK" || response?.recommendation === "FLAG") {
    detected.push("intent_classifier");
  }
  if (response?.primaryIntent && response.primaryIntent !== "BENIGN_DEV") {
    detected.push("intent_classifier");
  }

  // Output filter (command blocking)
  if (response?.verdict === "BLOCK" && endpoint === "test-command") {
    detected.push("output_filter");
  }
  if (response?.allowed === false && endpoint === "test-command") {
    detected.push("output_filter");
  }

  // Package filter
  if (response?.allowed === false && endpoint === "test-package") {
    detected.push("package_filter");
  }
  if (response?.blockedPackages?.length > 0) {
    detected.push("package_filter");
  }

  // Secret detector
  if (response?.secrets?.detected) {
    detected.push("secret_detector");
  }

  return [...new Set(detected)];
}

// ── Run single unit test ──────────────────────────────────────────────

async function runUnitTest(vector: AttackVector, config: RunConfig): Promise<TestResult> {
  if (!vector.unitEndpoint || !vector.unitPayload) {
    return {
      vectorId: vector.id,
      vectorName: vector.name,
      category: vector.category,
      severity: vector.severity,
      mode: "unit",
      passed: false,
      expectedLayers: vector.expectedLayers,
      detectedByLayers: [],
      missedByLayers: vector.expectedLayers,
      response: null,
      durationMs: 0,
      error: "No unit endpoint/payload defined",
    };
  }

  const endpoint = ENDPOINT_MAP[vector.unitEndpoint];
  if (!endpoint) {
    return {
      vectorId: vector.id,
      vectorName: vector.name,
      category: vector.category,
      severity: vector.severity,
      mode: "unit",
      passed: false,
      expectedLayers: vector.expectedLayers,
      detectedByLayers: [],
      missedByLayers: vector.expectedLayers,
      response: null,
      durationMs: 0,
      error: `Unknown endpoint: ${vector.unitEndpoint}`,
    };
  }

  const { status, data, durationMs } = await apiCall(endpoint, vector.unitPayload, config);

  if (status === 0) {
    return {
      vectorId: vector.id,
      vectorName: vector.name,
      category: vector.category,
      severity: vector.severity,
      mode: "unit",
      passed: false,
      expectedLayers: vector.expectedLayers,
      detectedByLayers: [],
      missedByLayers: vector.expectedLayers,
      response: data,
      durationMs,
      error: `API call failed: ${data?.error || "connection refused"}`,
    };
  }

  // Evaluate pass criteria
  const { passed: criteriaPassed, details } = evaluateCriteria(data, vector.unitPassCriteria);

  // Infer which layers detected this attack
  const detectedByLayers = inferDetectedLayers(vector, data, vector.unitEndpoint);

  // Compute layers that should have caught this but didn't
  // Only check layers relevant to this unit endpoint
  const testableLayersForEndpoint: Record<string, SecurityLayer[]> = {
    "test-input": ["input_firewall", "secret_detector"],
    "test-command": ["output_filter"],
    "test-package": ["package_filter"],
    "test-injection": ["injection_detector"],
    "classify-intent": ["intent_classifier"],
  };
  const relevantExpected = vector.expectedLayers.filter((l) =>
    (testableLayersForEndpoint[vector.unitEndpoint!] || []).includes(l)
  );
  const missedByLayers = relevantExpected.filter((l) => !detectedByLayers.includes(l));

  // For negative tests (no expected layers), pass = criteria met
  const isNegativeTest = vector.expectedLayers.length === 0;
  const passed = isNegativeTest ? criteriaPassed : (criteriaPassed && missedByLayers.length === 0);

  if (config.verbose) {
    for (const d of details) {
      console.log(`    ${DIM}${d}${NC}`);
    }
  }

  return {
    vectorId: vector.id,
    vectorName: vector.name,
    category: vector.category,
    severity: vector.severity,
    mode: "unit",
    passed,
    expectedLayers: vector.expectedLayers,
    detectedByLayers,
    missedByLayers,
    response: data,
    durationMs,
  };
}

// ── Run single E2E test ───────────────────────────────────────────────

async function runE2ETest(
  vector: AttackVector,
  config: RunConfig,
  projectId: string
): Promise<TestResult> {
  // E2E test sends the prompt through the full agent pipeline
  // The uncensored model will try to generate dangerous code
  // Our security stack should catch it at various layers

  const start = Date.now();

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (AUTH_TOKEN) {
      headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
    }

    const resp = await fetch(`${config.apiUrl}/api/agent/${projectId}/message`, {
      method: "POST",
      headers,
      body: JSON.stringify({ message: vector.prompt }),
      signal: AbortSignal.timeout(120_000), // 2 min timeout for LLM
    });

    // SSE response — collect all events
    const text = await resp.text();
    const events: any[] = [];
    const detectedLayers: SecurityLayer[] = [];

    for (const line of text.split("\n")) {
      if (line.startsWith("data: ") && line !== "data: [DONE]") {
        try {
          const event = JSON.parse(line.slice(6));
          events.push(event);

          // Analyze events for security detections
          if (event.type === "security_block") {
            if (event.data?.source === "firewall") detectedLayers.push("input_firewall");
            if (event.data?.source === "injection") detectedLayers.push("injection_detector");
            if (event.data?.source === "intent") detectedLayers.push("intent_classifier");
            if (event.data?.source === "command_filter") detectedLayers.push("output_filter");
            if (event.data?.source === "package_filter") detectedLayers.push("package_filter");
          }
          if (event.type === "error" && event.data?.message?.includes("blocked")) {
            detectedLayers.push("input_firewall");
          }
          if (event.type === "error" && event.data?.message?.includes("injection")) {
            detectedLayers.push("injection_detector");
          }
          if (event.type === "error" && event.data?.message?.includes("Intent classified")) {
            detectedLayers.push("intent_classifier");
          }
          if (event.type === "tool_result" && event.data?.blocked) {
            detectedLayers.push("output_filter");
          }
        } catch {}
      }
    }

    const durationMs = Date.now() - start;
    const uniqueLayers = [...new Set(detectedLayers)];
    const missedLayers = vector.expectedLayers.filter(
      (l) =>
        // Only count app-level layers as "missed" in E2E (not infra layers like Cilium/Tetragon)
        ["input_firewall", "injection_detector", "intent_classifier", "output_filter", "package_filter", "secret_detector", "trajectory_monitor"].includes(l) &&
        !uniqueLayers.includes(l)
    );

    // For negative tests: pass if no security blocks
    const isNegativeTest = vector.expectedLayers.length === 0;
    const hasSecurityBlock = events.some(
      (e) => e.type === "security_block" || (e.type === "error" && e.data?.message?.includes("blocked"))
    );
    const passed = isNegativeTest ? !hasSecurityBlock : uniqueLayers.length > 0;

    return {
      vectorId: vector.id,
      vectorName: vector.name,
      category: vector.category,
      severity: vector.severity,
      mode: "e2e",
      passed,
      expectedLayers: vector.expectedLayers,
      detectedByLayers: uniqueLayers,
      missedByLayers: missedLayers,
      response: { eventCount: events.length, events: events.slice(0, 5) },
      durationMs,
    };
  } catch (err: any) {
    return {
      vectorId: vector.id,
      vectorName: vector.name,
      category: vector.category,
      severity: vector.severity,
      mode: "e2e",
      passed: false,
      expectedLayers: vector.expectedLayers,
      detectedByLayers: [],
      missedByLayers: vector.expectedLayers,
      response: null,
      durationMs: Date.now() - start,
      error: err.message,
    };
  }
}

// ── Generate report ───────────────────────────────────────────────────

function generateReport(results: TestResult[], config: RunConfig): TestReport {
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed && !r.error).length;
  const errored = results.filter((r) => !!r.error).length;
  const totalDurationMs = results.reduce((sum, r) => sum + r.durationMs, 0);

  // Layer coverage
  const layerCoverage: Record<string, { tested: number; caught: number; missed: number; rate: string }> = {};
  for (const r of results) {
    for (const layer of r.expectedLayers) {
      if (!layerCoverage[layer]) {
        layerCoverage[layer] = { tested: 0, caught: 0, missed: 0, rate: "0%" };
      }
      layerCoverage[layer].tested++;
      if (r.detectedByLayers.includes(layer)) {
        layerCoverage[layer].caught++;
      } else {
        layerCoverage[layer].missed++;
      }
    }
  }
  for (const [, v] of Object.entries(layerCoverage)) {
    v.rate = v.tested > 0 ? `${Math.round((v.caught / v.tested) * 100)}%` : "N/A";
  }

  // Category coverage
  const categoryCoverage: Record<string, { tested: number; passed: number; failed: number }> = {};
  for (const r of results) {
    if (!categoryCoverage[r.category]) {
      categoryCoverage[r.category] = { tested: 0, passed: 0, failed: 0 };
    }
    categoryCoverage[r.category].tested++;
    if (r.passed) categoryCoverage[r.category].passed++;
    else categoryCoverage[r.category].failed++;
  }

  // Gaps — failed tests with missed layers
  const gaps = results
    .filter((r) => !r.passed && r.missedByLayers.length > 0)
    .map((r) => ({
      vectorId: r.vectorId,
      name: r.vectorName,
      severity: r.severity,
      missedLayers: r.missedByLayers as string[],
    }));

  // Recommendations
  const recommendations: string[] = [];
  const failedCritical = results.filter((r) => !r.passed && r.severity === "critical");
  if (failedCritical.length > 0) {
    recommendations.push(
      `CRITICAL: ${failedCritical.length} critical attack vectors not fully detected. Fix immediately.`
    );
  }

  for (const [layer, coverage] of Object.entries(layerCoverage)) {
    if (coverage.missed > 0) {
      recommendations.push(
        `Layer "${layer}" missed ${coverage.missed}/${coverage.tested} attacks (${coverage.rate} catch rate). Review patterns.`
      );
    }
  }

  if (passed === results.length) {
    recommendations.push("All tests passed. Security stack is comprehensive for tested vectors.");
  }

  return {
    timestamp: new Date().toISOString(),
    config,
    model: config.model,
    summary: {
      total: results.length,
      passed,
      failed: failed + errored,
      skipped: 0,
      passRate: `${Math.round((passed / results.length) * 100)}%`,
      duration: `${(totalDurationMs / 1000).toFixed(1)}s`,
    },
    layerCoverage,
    categoryCoverage,
    results,
    gaps,
    recommendations,
  };
}

// ── Print results ─────────────────────────────────────────────────────

function printResult(result: TestResult) {
  const icon = result.passed ? `${GREEN}[PASS]${NC}` : `${RED}[FAIL]${NC}`;
  const sevColor =
    result.severity === "critical"
      ? RED
      : result.severity === "high"
        ? YELLOW
        : DIM;
  const sev = `${sevColor}${result.severity.toUpperCase()}${NC}`;

  console.log(`  ${icon} ${result.vectorId} ${result.vectorName} ${DIM}(${sev}${DIM}, ${result.durationMs}ms)${NC}`);

  if (!result.passed) {
    if (result.error) {
      console.log(`    ${RED}Error: ${result.error}${NC}`);
    }
    if (result.missedByLayers.length > 0) {
      console.log(`    ${YELLOW}Missed by: ${result.missedByLayers.join(", ")}${NC}`);
    }
    if (result.detectedByLayers.length > 0) {
      console.log(`    ${GREEN}Caught by: ${result.detectedByLayers.join(", ")}${NC}`);
    }
  }
}

function printReport(report: TestReport) {
  console.log("");
  console.log(`${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}`);
  console.log(`${CYAN}║${NC}  ${BOLD}Security Regression Test Report${NC}                             ${CYAN}║${NC}`);
  console.log(`${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}`);
  console.log("");
  console.log(`  Model:    ${report.model || "N/A (unit tests only)"}`);
  console.log(`  Mode:     ${report.config.mode}`);
  console.log(`  Duration: ${report.summary.duration}`);
  console.log("");

  // Summary bar
  const pct = report.summary.total > 0 ? Math.round((report.summary.passed / report.summary.total) * 100) : 0;
  const barColor = pct === 100 ? GREEN : pct >= 80 ? YELLOW : RED;
  console.log(
    `  ${barColor}${report.summary.passed}/${report.summary.total} passed (${report.summary.passRate})${NC}` +
      (report.summary.failed > 0 ? `  ${RED}${report.summary.failed} failed${NC}` : "")
  );
  console.log("");

  // Layer coverage table
  console.log(`${BOLD}  Layer Coverage:${NC}`);
  console.log(`  ${"─".repeat(60)}`);
  for (const [layer, cov] of Object.entries(report.layerCoverage)) {
    const rateColor = cov.rate === "100%" ? GREEN : cov.missed > 0 ? RED : YELLOW;
    console.log(
      `  ${layer.padEnd(25)} ${rateColor}${cov.rate.padStart(5)}${NC}  (${cov.caught}/${cov.tested} caught)`
    );
  }
  console.log("");

  // Category coverage
  console.log(`${BOLD}  Category Coverage:${NC}`);
  console.log(`  ${"─".repeat(60)}`);
  for (const [cat, cov] of Object.entries(report.categoryCoverage)) {
    const icon = cov.failed === 0 ? GREEN + "✓" : RED + "✗";
    console.log(
      `  ${icon}${NC} ${cat.padEnd(30)} ${cov.passed}/${cov.tested} passed`
    );
  }
  console.log("");

  // Gaps
  if (report.gaps.length > 0) {
    console.log(`${RED}${BOLD}  Security Gaps (Action Required):${NC}`);
    console.log(`  ${"─".repeat(60)}`);
    for (const gap of report.gaps) {
      console.log(`  ${RED}!${NC} ${gap.vectorId} ${gap.name} [${gap.severity}]`);
      console.log(`    Missed by: ${gap.missedLayers.join(", ")}`);
    }
    console.log("");
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    console.log(`${BOLD}  Recommendations:${NC}`);
    for (const rec of report.recommendations) {
      const icon = rec.startsWith("CRITICAL") ? RED + "!" : rec.startsWith("All tests") ? GREEN + "✓" : YELLOW + "→";
      console.log(`  ${icon}${NC} ${rec}`);
    }
  }

  console.log("");
}

// ── Parse CLI args ────────────────────────────────────────────────────

function parseArgs(): RunConfig {
  const args = process.argv.slice(2);
  const config: RunConfig = {
    mode: "unit",
    generateReport: false,
    verbose: false,
    apiUrl: API_URL,
  };

  for (const arg of args) {
    if (arg.startsWith("--mode=")) config.mode = arg.split("=")[1] as any;
    if (arg.startsWith("--model=")) config.model = arg.split("=")[1];
    if (arg.startsWith("--category="))
      config.categories = arg.split("=")[1].split(",") as ThreatCategory[];
    if (arg.startsWith("--id=")) config.ids = arg.split("=")[1].split(",");
    if (arg === "--report") config.generateReport = true;
    if (arg === "--verbose" || arg === "-v") config.verbose = true;
    if (arg.startsWith("--api=")) config.apiUrl = arg.split("=")[1];
  }

  return config;
}

// ── Main ──────────────────────────────────────────────────────────────

async function main() {
  const config = parseArgs();

  console.log("");
  console.log(`${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}`);
  console.log(`${CYAN}║${NC}  ${BOLD}DevFactory Security Regression Test Suite${NC}                   ${CYAN}║${NC}`);
  console.log(`${CYAN}║${NC}  Defense-in-Depth vs Uncensored LLM                          ${CYAN}║${NC}`);
  console.log(`${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}`);
  console.log("");

  // Filter vectors
  let vectors = [...ATTACK_VECTORS];

  if (config.ids) {
    vectors = vectors.filter((v) => config.ids!.includes(v.id));
  }
  if (config.categories) {
    vectors = vectors.filter((v) => config.categories!.includes(v.category));
  }

  // Filter by mode
  if (config.mode === "unit") {
    vectors = vectors.filter((v) => v.mode === "unit" || v.mode === "both");
  } else if (config.mode === "e2e") {
    vectors = vectors.filter((v) => v.mode === "e2e" || v.mode === "both");
  }

  const stats = getVectorStats();
  console.log(`  Total vectors: ${stats.total}`);
  console.log(`  Running: ${vectors.length} (mode=${config.mode})`);
  if (config.model) console.log(`  Model: ${config.model}`);
  console.log(`  API: ${config.apiUrl}`);
  console.log("");

  // Verify API is reachable
  try {
    const healthResp = await fetch(`${config.apiUrl}/api/health`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!healthResp.ok) {
      console.log(`${RED}API health check failed (status ${healthResp.status})${NC}`);
      process.exit(1);
    }
    console.log(`  ${GREEN}API health: OK${NC}`);

    // Auto-fetch auth token if not provided
    await ensureAuthToken();
    console.log(`  ${AUTH_TOKEN ? GREEN + "Auth token: acquired" : YELLOW + "Auth token: none"}${NC}`);
    console.log("");
  } catch (err: any) {
    console.log(`${RED}Cannot reach API at ${config.apiUrl}: ${err.message}${NC}`);
    console.log(`Start the server first: npm run dev:server`);
    process.exit(1);
  }

  const results: TestResult[] = [];
  let currentCategory = "";

  for (const vector of vectors) {
    // Print category header
    if (vector.category !== currentCategory) {
      currentCategory = vector.category;
      console.log(`${YELLOW}=== ${currentCategory} ===${NC}`);
    }

    if (config.mode === "unit" || (config.mode === "both" && (vector.mode === "unit" || vector.mode === "both"))) {
      // Run unit test
      if (vector.unitEndpoint) {
        const result = await runUnitTest(vector, config);
        results.push(result);
        printResult(result);
      }
    }

    if (config.mode === "e2e" || (config.mode === "both" && (vector.mode === "e2e" || vector.mode === "both"))) {
      // E2E tests need a project ID — for now, use a well-known test project
      // In real usage, create a workspace first
      const projectId = process.env.TEST_PROJECT_ID || "e2e-security-test";
      const result = await runE2ETest(vector, config, projectId);
      results.push(result);
      printResult(result);
    }
  }

  // Generate and print report
  const report = generateReport(results, config);
  printReport(report);

  // Write JSON report
  if (config.generateReport) {
    const fs = await import("fs");
    const reportPath = `tests/e2e-security/reports/report-${Date.now()}.json`;
    fs.mkdirSync("tests/e2e-security/reports", { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`  ${GREEN}Report saved: ${reportPath}${NC}`);
  }

  // Exit with failure if any critical vectors failed
  const criticalFailures = results.filter((r) => !r.passed && r.severity === "critical");
  if (criticalFailures.length > 0) {
    console.log(`\n${RED}${BOLD}FAILED: ${criticalFailures.length} critical security vectors not detected.${NC}\n`);
    process.exit(1);
  }

  if (results.every((r) => r.passed)) {
    console.log(`\n${GREEN}${BOLD}ALL SECURITY TESTS PASSED.${NC}\n`);
  }
}

main().catch((err) => {
  console.error(`${RED}Fatal: ${err.message}${NC}`);
  process.exit(1);
});
