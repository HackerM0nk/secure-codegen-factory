// src/server/security/sbom-generator.ts
// Generates CycloneDX 1.5 JSON SBOM from package.json + package-lock.json

import { createHash } from "crypto";

export interface CycloneDXComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  scope?: "required" | "optional" | "excluded";
  licenses?: Array<{ license: { id?: string; name?: string } }>;
  hashes?: Array<{ alg: string; content: string }>;
  description?: string;
}

export interface CycloneDXBom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component?: {
      type: "application";
      name: string;
      version: string;
    };
  };
  components: CycloneDXComponent[];
  dependencies: Array<{
    ref: string;
    dependsOn: string[];
  }>;
}

export interface SbomResult {
  tool: "sbom";
  bom: CycloneDXBom;
  componentCount: number;
  durationMs: number;
}

function makePurl(name: string, version: string): string {
  // Package URL spec: pkg:npm/name@version or pkg:npm/%40scope/name@version
  const encoded = name.startsWith("@")
    ? `%40${name.slice(1).replace("/", "%2F")}`
    : name;
  return `pkg:npm/${encoded}@${version}`;
}

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Generate a CycloneDX 1.5 SBOM from package.json and package-lock.json content.
 */
export function generateSbom(
  packageJsonStr: string,
  lockfileStr?: string
): SbomResult {
  const start = Date.now();
  const components: CycloneDXComponent[] = [];
  const depRefs: Array<{ ref: string; dependsOn: string[] }> = [];

  let pkg: any;
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    pkg = { name: "unknown", version: "0.0.0" };
  }

  const rootRef = makePurl(pkg.name || "unknown", pkg.version || "0.0.0");
  const rootDependsOn: string[] = [];

  // Add direct dependencies from package.json
  const addDeps = (
    deps: Record<string, string> | undefined,
    scope: "required" | "optional"
  ) => {
    if (!deps) return;
    for (const [name, versionRange] of Object.entries(deps)) {
      const version = versionRange.replace(/^[\^~>=<]/, "").replace(/\s.*/, "");
      const purl = makePurl(name, version);
      rootDependsOn.push(purl);
      components.push({
        type: "library",
        name,
        version,
        purl,
        scope,
      });
    }
  };

  addDeps(pkg.dependencies, "required");
  addDeps(pkg.devDependencies, "optional");

  // If we have a lockfile, enrich with exact versions and transitive deps
  if (lockfileStr) {
    try {
      const lockfile = JSON.parse(lockfileStr);
      const existing = new Set(components.map((c) => c.name));

      // npm v7+ lockfileVersion 2/3
      if (lockfile.packages) {
        for (const [path, info] of Object.entries<any>(lockfile.packages)) {
          if (!path) continue;
          const name = path.replace(/^node_modules\//, "").replace(/.*node_modules\//, "");
          if (!name || existing.has(name)) {
            // Update version for existing entries
            const comp = components.find((c) => c.name === name);
            if (comp && info.version) {
              comp.version = info.version;
              comp.purl = makePurl(name, info.version);
            }
            continue;
          }

          if (info.version) {
            existing.add(name);
            const purl = makePurl(name, info.version);
            const comp: CycloneDXComponent = {
              type: "library",
              name,
              version: info.version,
              purl,
              scope: info.dev ? "optional" : "required",
            };

            // Add license if available
            if (info.license) {
              comp.licenses = [
                { license: { id: typeof info.license === "string" ? info.license : info.license.type || info.license } },
              ];
            }

            // Add integrity hash
            if (info.integrity) {
              const [alg, hash] = info.integrity.split("-", 2);
              if (alg && hash) {
                comp.hashes = [{ alg: alg.toUpperCase(), content: hash }];
              }
            }

            components.push(comp);
          }
        }
      }
    } catch {
      // Lockfile parsing failed, continue with package.json deps only
    }
  }

  depRefs.push({ ref: rootRef, dependsOn: rootDependsOn });

  const bom: CycloneDXBom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "DevFactory",
          name: "sbom-generator",
          version: "1.0.0",
        },
      ],
      component: {
        type: "application",
        name: pkg.name || "unknown",
        version: pkg.version || "0.0.0",
      },
    },
    components,
    dependencies: depRefs,
  };

  return {
    tool: "sbom",
    bom,
    componentCount: components.length,
    durationMs: Date.now() - start,
  };
}
