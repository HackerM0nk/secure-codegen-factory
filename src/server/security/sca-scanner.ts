// src/server/security/sca-scanner.ts
// Software Composition Analysis — parses npm audit output into structured vulnerabilities

export interface ScaVulnerability {
  name: string;
  severity: "critical" | "high" | "moderate" | "low" | "info";
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean;
  via: string[];
  isDirect: boolean;
  cvss?: number;
  cwe?: string[];
}

export interface ScaScanResult {
  tool: "sca";
  vulnerabilities: ScaVulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    moderate: number;
    low: number;
    info: number;
  };
  durationMs: number;
  passed: boolean;
}

/**
 * Parse the JSON output of `npm audit --json` (npm v7+ format).
 */
export function parseNpmAudit(auditJson: string): ScaScanResult {
  const start = Date.now();
  const vulnerabilities: ScaVulnerability[] = [];

  try {
    const audit = JSON.parse(auditJson);

    // npm v7+ format uses audit.vulnerabilities (object keyed by package name)
    if (audit.vulnerabilities && typeof audit.vulnerabilities === "object") {
      for (const [name, vuln] of Object.entries<any>(audit.vulnerabilities)) {
        const viaList: string[] = [];
        if (Array.isArray(vuln.via)) {
          for (const v of vuln.via) {
            if (typeof v === "string") {
              viaList.push(v);
            } else if (v.title) {
              viaList.push(v.title);
            }
          }
        }

        vulnerabilities.push({
          name,
          severity: vuln.severity || "info",
          title: viaList[0] || `Vulnerability in ${name}`,
          url: Array.isArray(vuln.via)
            ? vuln.via.find((v: any) => v?.url)?.url || ""
            : "",
          range: vuln.range || "*",
          fixAvailable: !!vuln.fixAvailable,
          via: viaList,
          isDirect: vuln.isDirect || false,
          cvss: Array.isArray(vuln.via)
            ? vuln.via.find((v: any) => v?.cvss?.score)?.cvss?.score
            : undefined,
          cwe: Array.isArray(vuln.via)
            ? vuln.via
                .filter((v: any) => Array.isArray(v?.cwe))
                .flatMap((v: any) => v.cwe)
            : undefined,
        });
      }
    }

    // Fallback: npm v6 format uses audit.advisories
    else if (audit.advisories && typeof audit.advisories === "object") {
      for (const advisory of Object.values<any>(audit.advisories)) {
        vulnerabilities.push({
          name: advisory.module_name || "unknown",
          severity: advisory.severity || "info",
          title: advisory.title || "Unknown vulnerability",
          url: advisory.url || "",
          range: advisory.vulnerable_versions || "*",
          fixAvailable: !!advisory.patched_versions && advisory.patched_versions !== "<0.0.0",
          via: [advisory.title || ""],
          isDirect: false,
          cvss: advisory.cvss?.score,
          cwe: advisory.cwe ? [advisory.cwe] : undefined,
        });
      }
    }
  } catch {
    // If parsing fails, return empty result
  }

  const summary = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    moderate: vulnerabilities.filter((v) => v.severity === "moderate").length,
    low: vulnerabilities.filter((v) => v.severity === "low").length,
    info: vulnerabilities.filter((v) => v.severity === "info").length,
  };

  return {
    tool: "sca",
    vulnerabilities,
    summary,
    durationMs: Date.now() - start,
    passed: summary.critical === 0,
  };
}

/**
 * Parse a package-lock.json to extract all transitive dependencies.
 * Returns a map of package name → version.
 */
export function parseTransitiveDeps(
  lockfileJson: string
): Map<string, string> {
  const deps = new Map<string, string>();

  try {
    const lockfile = JSON.parse(lockfileJson);

    // npm v7+ lockfileVersion 2/3 uses "packages"
    if (lockfile.packages) {
      for (const [path, pkg] of Object.entries<any>(lockfile.packages)) {
        if (!path) continue; // skip root ""
        const name = path.replace(/^node_modules\//, "");
        if (name && pkg.version) {
          deps.set(name, pkg.version);
        }
      }
    }

    // npm v1 lockfile uses "dependencies"
    else if (lockfile.dependencies) {
      const walk = (depMap: Record<string, any>, prefix = "") => {
        for (const [name, info] of Object.entries<any>(depMap)) {
          const fullName = prefix ? `${prefix}/${name}` : name;
          if (info.version) deps.set(fullName, info.version);
          if (info.dependencies) walk(info.dependencies, fullName);
        }
      };
      walk(lockfile.dependencies);
    }
  } catch {
    // Parsing failed
  }

  return deps;
}
