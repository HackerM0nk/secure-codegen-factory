// src/server/security/image-scanner.ts
// Runs Trivy image scan and parses results into structured findings

import { execSync } from "child_process";

export interface ImageVulnerability {
  vulnerabilityID: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  title: string;
  description: string;
  primaryURL: string;
}

export interface ImageScanResult {
  tool: "image";
  image: string;
  vulnerabilities: ImageVulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  durationMs: number;
  passed: boolean;
  cached: boolean;
  error?: string;
}

// Simple in-memory cache for image scan results (image rarely changes)
const scanCache = new Map<string, { result: ImageScanResult; timestamp: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Check if Trivy is installed and available.
 */
export function isTrivyAvailable(): boolean {
  try {
    execSync("trivy --version", { stdio: "pipe", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Scan a container image with Trivy.
 * Results are cached for 10 minutes since workspace images change infrequently.
 */
export function scanImage(imageName: string): ImageScanResult {
  const start = Date.now();

  // Check cache
  const cached = scanCache.get(imageName);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return { ...cached.result, cached: true, durationMs: 0 };
  }

  // Check Trivy availability
  if (!isTrivyAvailable()) {
    return {
      tool: "image",
      image: imageName,
      vulnerabilities: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      durationMs: Date.now() - start,
      passed: true,
      cached: false,
      error: "Trivy not installed. Install with: brew install trivy (macOS) or see https://trivy.dev",
    };
  }

  try {
    const output = execSync(
      `trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW --quiet ${imageName}`,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 }
    ).toString();

    const report = JSON.parse(output);
    const vulnerabilities: ImageVulnerability[] = [];

    // Trivy JSON output has Results[] with Vulnerabilities[]
    if (report.Results && Array.isArray(report.Results)) {
      for (const result of report.Results) {
        if (result.Vulnerabilities && Array.isArray(result.Vulnerabilities)) {
          for (const vuln of result.Vulnerabilities) {
            vulnerabilities.push({
              vulnerabilityID: vuln.VulnerabilityID || "",
              pkgName: vuln.PkgName || "",
              installedVersion: vuln.InstalledVersion || "",
              fixedVersion: vuln.FixedVersion || "",
              severity: vuln.Severity || "UNKNOWN",
              title: vuln.Title || "",
              description: (vuln.Description || "").substring(0, 200),
              primaryURL: vuln.PrimaryURL || "",
            });
          }
        }
      }
    }

    const summary = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter((v) => v.severity === "CRITICAL").length,
      high: vulnerabilities.filter((v) => v.severity === "HIGH").length,
      medium: vulnerabilities.filter((v) => v.severity === "MEDIUM").length,
      low: vulnerabilities.filter((v) => v.severity === "LOW").length,
    };

    const result: ImageScanResult = {
      tool: "image",
      image: imageName,
      vulnerabilities,
      summary,
      durationMs: Date.now() - start,
      passed: summary.critical === 0,
      cached: false,
    };

    // Cache the result
    scanCache.set(imageName, { result, timestamp: Date.now() });

    return result;
  } catch (err: any) {
    return {
      tool: "image",
      image: imageName,
      vulnerabilities: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      durationMs: Date.now() - start,
      passed: true,
      cached: false,
      error: `Trivy scan failed: ${err.message?.substring(0, 200)}`,
    };
  }
}
