// src/server/security/scanner.ts
// Unified security scanner orchestrator — runs SAST, SCA, secrets, SBOM, and image scans

import { scanFiles, type SastScanResult } from "./sast-scanner";
import { parseNpmAudit, type ScaScanResult } from "./sca-scanner";
import { generateSbom, type SbomResult } from "./sbom-generator";
import { scanForSecrets, type SecretScanResult } from "./secret-scanner";
import { scanImage, type ImageScanResult } from "./image-scanner";
import { execInWorkspace, readFileFromWorkspace } from "../services/workspace";

// ── Types ─────────────────────────────────────────────────────────────

export interface ScanOptions {
  sast?: boolean;
  sca?: boolean;
  secrets?: boolean;
  sbom?: boolean;
  image?: boolean;
}

export interface FullScanResult {
  projectId: string;
  timestamp: string;
  durationMs: number;
  passed: boolean;
  verdict: "PASS" | "WARN" | "BLOCK";
  sast?: SastScanResult;
  sca?: ScaScanResult;
  secrets?: SecretScanResult;
  sbom?: SbomResult;
  image?: ImageScanResult;
  summary: {
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    totalFindings: number;
  };
}

const DEFAULT_OPTIONS: ScanOptions = {
  sast: true,
  sca: true,
  secrets: true,
  sbom: true,
  image: false, // opt-in, requires Trivy
};

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Recursively collect all file contents from a workspace container.
 * Uses find + readFileFromWorkspace since listFilesInWorkspace returns raw strings.
 */
async function collectWorkspaceFiles(
  containerName: string
): Promise<Map<string, string>> {
  const files = new Map<string, string>();

  try {
    const result = await execInWorkspace(
      containerName,
      `find /workspace -type f \\( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.json' -o -name '*.env*' -o -name '*.py' -o -name '*.sh' -o -name '*.yaml' -o -name '*.yml' -o -name '*.html' -o -name '*.css' -o -name '*.sql' \\) -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/.next/*' -not -name 'package-lock.json' | head -300`
    );

    const paths = result.stdout.split("\n").filter(Boolean);

    for (const filePath of paths) {
      try {
        const content = await readFileFromWorkspace(containerName, filePath);
        if (content && content.length < 500_000) {
          files.set(filePath.replace(/^\/workspace\/?/, ""), content);
        }
      } catch {
        // Skip unreadable
      }
    }
  } catch {
    // find failed
  }

  return files;
}

/**
 * Collect files from the platform's own source (for self-scan).
 */
async function collectLocalFiles(
  basePath: string
): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  const fs = await import("fs/promises");
  const path = await import("path");

  const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", ".devfactory"]);

  async function walk(dirPath: string) {
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (SKIP.has(entry.name)) continue;
          await walk(path.join(dirPath, entry.name));
        } else {
          const ext = entry.name.split(".").pop() || "";
          if (["png", "jpg", "gif", "ico", "woff", "woff2", "ttf", "map", "lock"].includes(ext)) continue;

          try {
            const fullPath = path.join(dirPath, entry.name);
            const content = await fs.readFile(fullPath, "utf-8");
            if (content.length < 500_000) {
              const relativePath = fullPath.replace(basePath + "/", "");
              files.set(relativePath, content);
            }
          } catch {
            // Skip unreadable
          }
        }
      }
    } catch {
      // Skip inaccessible dirs
    }
  }

  await walk(basePath);
  return files;
}

// ── Main Scan Functions ───────────────────────────────────────────────

/**
 * Run a full security scan on a workspace project.
 */
export async function scanWorkspace(
  projectId: string,
  containerName: string,
  options: ScanOptions = DEFAULT_OPTIONS
): Promise<FullScanResult> {
  const start = Date.now();
  const result: FullScanResult = {
    projectId,
    timestamp: new Date().toISOString(),
    durationMs: 0,
    passed: true,
    verdict: "PASS",
    summary: { criticalFindings: 0, highFindings: 0, mediumFindings: 0, lowFindings: 0, totalFindings: 0 },
  };

  // Collect workspace files for SAST and secrets scanning
  const files = (options.sast || options.secrets)
    ? await collectWorkspaceFiles(containerName)
    : new Map<string, string>();

  // Run scans in parallel where possible
  const scans: Promise<void>[] = [];

  // SAST
  if (options.sast) {
    scans.push((async () => {
      result.sast = scanFiles(files);
    })());
  }

  // Secrets
  if (options.secrets) {
    scans.push((async () => {
      result.secrets = scanForSecrets(files);
    })());
  }

  // SCA (npm audit)
  if (options.sca) {
    scans.push((async () => {
      try {
        const auditResult = await execInWorkspace(
          containerName,
          "cd /workspace && npm audit --json 2>/dev/null || true"
        );
        result.sca = parseNpmAudit(auditResult.stdout);
      } catch {
        result.sca = {
          tool: "sca",
          vulnerabilities: [],
          summary: { total: 0, critical: 0, high: 0, moderate: 0, low: 0, info: 0 },
          durationMs: 0,
          passed: true,
        };
      }
    })());
  }

  // SBOM
  if (options.sbom) {
    scans.push((async () => {
      try {
        const pkgJson = await readFileFromWorkspace(containerName, "/workspace/package.json");
        let lockJson: string | undefined;
        try {
          lockJson = await readFileFromWorkspace(containerName, "/workspace/package-lock.json");
        } catch {}
        result.sbom = generateSbom(pkgJson, lockJson);
      } catch {
        // No package.json, skip SBOM
      }
    })());
  }

  // Image scan
  if (options.image) {
    scans.push((async () => {
      const imageName = process.env.WORKSPACE_IMAGE || "devfactory-workspace:latest";
      result.image = scanImage(imageName);
    })());
  }

  await Promise.all(scans);

  // Aggregate findings
  let critical = 0, high = 0, medium = 0, low = 0;

  if (result.sast) {
    critical += result.sast.findings.filter((f) => f.severity === "critical").length;
    high += result.sast.findings.filter((f) => f.severity === "high").length;
    medium += result.sast.findings.filter((f) => f.severity === "medium").length;
    low += result.sast.findings.filter((f) => f.severity === "low").length;
  }
  if (result.sca) {
    critical += result.sca.summary.critical;
    high += result.sca.summary.high;
    medium += result.sca.summary.moderate;
    low += result.sca.summary.low;
  }
  if (result.secrets) {
    critical += result.secrets.findings.filter((f) => f.severity === "critical").length;
    high += result.secrets.findings.filter((f) => f.severity === "high").length;
    medium += result.secrets.findings.filter((f) => f.severity === "medium").length;
  }
  if (result.image) {
    critical += result.image.summary.critical;
    high += result.image.summary.high;
    medium += result.image.summary.medium;
    low += result.image.summary.low;
  }

  result.summary = {
    criticalFindings: critical,
    highFindings: high,
    mediumFindings: medium,
    lowFindings: low,
    totalFindings: critical + high + medium + low,
  };

  result.passed = critical === 0;
  result.verdict = critical > 0 ? "BLOCK" : (high > 0 ? "WARN" : "PASS");
  result.durationMs = Date.now() - start;

  return result;
}

/**
 * Run a self-scan on the DevFactory platform source code itself.
 */
export async function scanPlatform(): Promise<FullScanResult> {
  const start = Date.now();
  const basePath = process.cwd();
  const files = await collectLocalFiles(basePath);

  const result: FullScanResult = {
    projectId: "platform-self-scan",
    timestamp: new Date().toISOString(),
    durationMs: 0,
    passed: true,
    verdict: "PASS",
    summary: { criticalFindings: 0, highFindings: 0, mediumFindings: 0, lowFindings: 0, totalFindings: 0 },
  };

  result.sast = scanFiles(files);
  result.secrets = scanForSecrets(files);

  let critical = 0, high = 0, medium = 0, low = 0;

  critical += result.sast.findings.filter((f) => f.severity === "critical").length;
  high += result.sast.findings.filter((f) => f.severity === "high").length;
  medium += result.sast.findings.filter((f) => f.severity === "medium").length;
  low += result.sast.findings.filter((f) => f.severity === "low").length;

  critical += result.secrets.findings.filter((f) => f.severity === "critical").length;
  high += result.secrets.findings.filter((f) => f.severity === "high").length;
  medium += result.secrets.findings.filter((f) => f.severity === "medium").length;

  result.summary = { criticalFindings: critical, highFindings: high, mediumFindings: medium, lowFindings: low, totalFindings: critical + high + medium + low };
  result.passed = critical === 0;
  result.verdict = critical > 0 ? "BLOCK" : (high > 0 ? "WARN" : "PASS");
  result.durationMs = Date.now() - start;

  return result;
}
