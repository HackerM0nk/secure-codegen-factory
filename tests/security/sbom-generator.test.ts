// tests/security/sbom-generator.test.ts
// Unit tests for CycloneDX SBOM generation

import { generateSbom } from "../../src/server/security/sbom-generator";

describe("SBOM Generator", () => {
  const basicPackageJson = JSON.stringify({
    name: "test-app",
    version: "1.0.0",
    dependencies: {
      express: "^4.18.0",
      react: "^18.2.0",
    },
    devDependencies: {
      typescript: "^5.0.0",
    },
  });

  test("generates valid CycloneDX 1.5 structure", () => {
    const result = generateSbom(basicPackageJson);
    expect(result.bom.bomFormat).toBe("CycloneDX");
    expect(result.bom.specVersion).toBe("1.5");
    expect(result.bom.version).toBe(1);
    expect(result.bom.serialNumber).toMatch(/^urn:uuid:/);
  });

  test("includes metadata with tool info", () => {
    const result = generateSbom(basicPackageJson);
    expect(result.bom.metadata.tools[0].vendor).toBe("DevFactory");
    expect(result.bom.metadata.tools[0].name).toBe("sbom-generator");
    expect(result.bom.metadata.component?.name).toBe("test-app");
    expect(result.bom.metadata.component?.version).toBe("1.0.0");
    expect(result.bom.metadata.timestamp).toBeTruthy();
  });

  test("includes all dependencies as components", () => {
    const result = generateSbom(basicPackageJson);
    expect(result.componentCount).toBe(3);
    const names = result.bom.components.map((c) => c.name);
    expect(names).toContain("express");
    expect(names).toContain("react");
    expect(names).toContain("typescript");
  });

  test("sets correct scope for dependencies", () => {
    const result = generateSbom(basicPackageJson);
    const express = result.bom.components.find((c) => c.name === "express");
    const ts = result.bom.components.find((c) => c.name === "typescript");
    expect(express?.scope).toBe("required");
    expect(ts?.scope).toBe("optional");
  });

  test("generates correct purl format", () => {
    const result = generateSbom(basicPackageJson);
    const express = result.bom.components.find((c) => c.name === "express");
    expect(express?.purl).toMatch(/^pkg:npm\/express@/);
  });

  test("handles scoped packages in purl", () => {
    const pkg = JSON.stringify({
      name: "my-app",
      version: "1.0.0",
      dependencies: {
        "@prisma/client": "^5.0.0",
      },
    });
    const result = generateSbom(pkg);
    const prisma = result.bom.components.find((c) => c.name === "@prisma/client");
    expect(prisma?.purl).toContain("%40prisma");
  });

  test("includes dependency graph", () => {
    const result = generateSbom(basicPackageJson);
    expect(result.bom.dependencies.length).toBeGreaterThan(0);
    expect(result.bom.dependencies[0].dependsOn.length).toBe(3);
  });

  test("enriches with lockfile data when provided", () => {
    const lockfile = JSON.stringify({
      packages: {
        "": { name: "test-app", version: "1.0.0" },
        "node_modules/express": { version: "4.18.2", license: "MIT", integrity: "sha512-abc123" },
        "node_modules/body-parser": { version: "1.20.1", license: "MIT" },
      },
    });
    const result = generateSbom(basicPackageJson, lockfile);
    // Should have express with exact version
    const express = result.bom.components.find((c) => c.name === "express");
    expect(express?.version).toBe("4.18.2");
    // Should include transitive dep
    const bodyParser = result.bom.components.find((c) => c.name === "body-parser");
    expect(bodyParser).toBeTruthy();
    expect(bodyParser?.licenses?.[0].license.id).toBe("MIT");
  });

  test("handles malformed package.json", () => {
    const result = generateSbom("not json");
    expect(result.bom.metadata.component?.name).toBe("unknown");
    expect(result.componentCount).toBe(0);
  });

  test("handles empty dependencies", () => {
    const pkg = JSON.stringify({ name: "empty", version: "0.0.0" });
    const result = generateSbom(pkg);
    expect(result.componentCount).toBe(0);
  });

  test("reports timing", () => {
    const result = generateSbom(basicPackageJson);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.tool).toBe("sbom");
  });
});
