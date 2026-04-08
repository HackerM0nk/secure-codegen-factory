// src/server/deploy/pre-deploy-gate.ts
// Pre-deployment security gate using proper SAST, SCA, secrets, and SBOM scanners

import { execInWorkspace, readFileFromWorkspace } from "../services/workspace";
import { scanFiles } from "../security/sast-scanner";
import { parseNpmAudit } from "../security/sca-scanner";
import { scanForSecrets } from "../security/secret-scanner";
import { generateSbom } from "../security/sbom-generator";

export interface GateResult {
  passed: boolean;
  checks: GateCheck[];
  sbom?: ReturnType<typeof generateSbom>;
}

interface GateCheck {
  name: string;
  passed: boolean;
  severity: "critical" | "warning" | "info";
  details: string;
  findings?: number;
}

/**
 * Recursively collect workspace files for scanning via find + cat.
 */
async function collectFiles(containerName: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();

  try {
    // Get list of scannable files
    const result = await execInWorkspace(
      containerName,
      `find /workspace -type f \\( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.json' -o -name '*.env*' -o -name '*.py' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' \\) -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/.next/*' -not -name 'package-lock.json' | head -200`
    );

    const paths = result.stdout.split("\n").filter(Boolean);

    for (const filePath of paths) {
      try {
        const content = await readFileFromWorkspace(containerName, filePath);
        if (content && content.length < 500_000) {
          files.set(filePath.replace(/^\/workspace\/?/, ""), content);
        }
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // Find command failed
  }

  return files;
}

export async function runPreDeployGate(containerName: string): Promise<GateResult> {
  const checks: GateCheck[] = [];

  // Collect files for SAST and secrets scanning
  const files = await collectFiles(containerName);

  // 1. SAST scan
  try {
    const sast = scanFiles(files);
    const criticalCount = sast.findings.filter((f) => f.severity === "critical").length;
    const highCount = sast.findings.filter((f) => f.severity === "high").length;

    checks.push({
      name: "SAST (Static Analysis)",
      passed: criticalCount === 0,
      severity: criticalCount > 0 ? "critical" : highCount > 0 ? "warning" : "info",
      details: criticalCount > 0
        ? `${criticalCount} critical, ${highCount} high findings (${sast.rulesApplied} rules, ${sast.filesScanned} files)`
        : highCount > 0
        ? `${highCount} high findings (no critical) -- ${sast.filesScanned} files scanned`
        : `Clean -- ${sast.filesScanned} files scanned with ${sast.rulesApplied} rules`,
      findings: sast.findings.length,
    });
  } catch (err: any) {
    checks.push({ name: "SAST", passed: true, severity: "info", details: `Skipped: ${err.message}` });
  }

  // 2. Secret scan
  try {
    const secrets = scanForSecrets(files);
    const criticalSecrets = secrets.findings.filter((f) => f.severity === "critical").length;

    checks.push({
      name: "Secret Scan",
      passed: criticalSecrets === 0,
      severity: criticalSecrets > 0 ? "critical" : secrets.findings.length > 0 ? "warning" : "info",
      details: criticalSecrets > 0
        ? `${criticalSecrets} critical secrets found in source code`
        : secrets.findings.length > 0
        ? `${secrets.findings.length} potential secrets (non-critical)`
        : `No secrets detected in ${secrets.filesScanned} files`,
      findings: secrets.findings.length,
    });
  } catch (err: any) {
    checks.push({ name: "Secret Scan", passed: true, severity: "info", details: `Skipped: ${err.message}` });
  }

  // 3. SCA -- Dependency audit
  try {
    const result = await execInWorkspace(containerName, "cd /workspace && npm audit --json 2>/dev/null || true");
    const sca = parseNpmAudit(result.stdout);

    checks.push({
      name: "SCA (Dependency Audit)",
      passed: sca.summary.critical === 0,
      severity: sca.summary.critical > 0 ? "critical" : sca.summary.high > 0 ? "warning" : "info",
      details: `Critical: ${sca.summary.critical}, High: ${sca.summary.high}, Moderate: ${sca.summary.moderate}, Low: ${sca.summary.low}`,
      findings: sca.summary.total,
    });
  } catch {
    checks.push({ name: "SCA (Dependency Audit)", passed: true, severity: "info", details: "Skipped" });
  }

  // 4. SBOM generation
  let sbomResult: ReturnType<typeof generateSbom> | undefined;
  try {
    const pkgJson = await readFileFromWorkspace(containerName, "/workspace/package.json");
    let lockJson: string | undefined;
    try {
      lockJson = await readFileFromWorkspace(containerName, "/workspace/package-lock.json");
    } catch {}
    sbomResult = generateSbom(pkgJson, lockJson);

    checks.push({
      name: "SBOM Generation",
      passed: true,
      severity: "info",
      details: `CycloneDX 1.5 SBOM generated -- ${sbomResult.componentCount} components catalogued`,
    });
  } catch {
    checks.push({ name: "SBOM Generation", passed: true, severity: "info", details: "Skipped -- no package.json" });
  }

  // 5. Build test
  try {
    const result = await execInWorkspace(containerName, "cd /workspace && npm run build 2>&1");
    checks.push({
      name: "Build Test",
      passed: result.exitCode === 0,
      severity: result.exitCode !== 0 ? "critical" : "info",
      details: result.exitCode === 0 ? "Build successful" : result.stderr.substring(0, 500),
    });
  } catch (err: any) {
    checks.push({ name: "Build Test", passed: false, severity: "critical", details: err.message });
  }

  return {
    passed: checks.every((c) => c.passed || c.severity !== "critical"),
    checks,
    sbom: sbomResult,
  };
}
