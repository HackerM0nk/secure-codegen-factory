// tests/security/sca-scanner.test.ts
// Unit tests for Software Composition Analysis scanner

import { parseNpmAudit, parseTransitiveDeps } from "../../src/server/security/sca-scanner";

describe("SCA Scanner", () => {
  describe("parseNpmAudit — npm v7+ format", () => {
    test("parses vulnerabilities from audit JSON", () => {
      const auditJson = JSON.stringify({
        vulnerabilities: {
          "lodash": {
            severity: "critical",
            via: [
              {
                title: "Prototype Pollution",
                url: "https://github.com/advisories/GHSA-123",
                cvss: { score: 9.8 },
                cwe: ["CWE-1321"],
              },
            ],
            range: "<4.17.21",
            fixAvailable: true,
            isDirect: true,
          },
          "minimist": {
            severity: "high",
            via: [{ title: "Prototype Pollution in minimist", url: "" }],
            range: "<1.2.6",
            fixAvailable: true,
            isDirect: false,
          },
        },
      });

      const result = parseNpmAudit(auditJson);
      expect(result.vulnerabilities).toHaveLength(2);
      expect(result.summary.critical).toBe(1);
      expect(result.summary.high).toBe(1);
      expect(result.passed).toBe(false); // has critical
    });

    test("passes when no critical vulnerabilities", () => {
      const auditJson = JSON.stringify({
        vulnerabilities: {
          "some-pkg": {
            severity: "moderate",
            via: ["some-dep"],
            range: "*",
            fixAvailable: false,
            isDirect: false,
          },
        },
      });

      const result = parseNpmAudit(auditJson);
      expect(result.passed).toBe(true);
      expect(result.summary.moderate).toBe(1);
    });

    test("handles empty audit", () => {
      const result = parseNpmAudit(JSON.stringify({ vulnerabilities: {} }));
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.passed).toBe(true);
    });

    test("extracts CVSS score and CWE", () => {
      const auditJson = JSON.stringify({
        vulnerabilities: {
          "vuln-pkg": {
            severity: "critical",
            via: [{ title: "RCE", cvss: { score: 9.8 }, cwe: ["CWE-78", "CWE-94"] }],
            range: "*",
            fixAvailable: true,
            isDirect: true,
          },
        },
      });

      const result = parseNpmAudit(auditJson);
      expect(result.vulnerabilities[0].cvss).toBe(9.8);
      expect(result.vulnerabilities[0].cwe).toEqual(["CWE-78", "CWE-94"]);
    });

    test("handles string via entries (transitive deps)", () => {
      const auditJson = JSON.stringify({
        vulnerabilities: {
          "parent-pkg": {
            severity: "high",
            via: ["child-vuln-pkg"],
            range: "*",
            fixAvailable: false,
            isDirect: true,
          },
        },
      });

      const result = parseNpmAudit(auditJson);
      expect(result.vulnerabilities[0].via).toEqual(["child-vuln-pkg"]);
    });
  });

  describe("parseNpmAudit — npm v6 format", () => {
    test("parses v6 advisory format", () => {
      const auditJson = JSON.stringify({
        advisories: {
          "1234": {
            module_name: "old-pkg",
            severity: "high",
            title: "XSS vulnerability",
            url: "https://npmjs.com/advisories/1234",
            vulnerable_versions: "<2.0.0",
            patched_versions: ">=2.0.0",
            cwe: "CWE-79",
            cvss: { score: 7.5 },
          },
        },
      });

      const result = parseNpmAudit(auditJson);
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0].name).toBe("old-pkg");
      expect(result.vulnerabilities[0].fixAvailable).toBe(true);
    });
  });

  describe("parseNpmAudit — error handling", () => {
    test("handles malformed JSON gracefully", () => {
      const result = parseNpmAudit("not json at all");
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.passed).toBe(true);
    });

    test("handles empty object", () => {
      const result = parseNpmAudit("{}");
      expect(result.vulnerabilities).toHaveLength(0);
      expect(result.passed).toBe(true);
    });
  });

  describe("parseTransitiveDeps", () => {
    test("parses npm v7+ lockfile packages", () => {
      const lockfile = JSON.stringify({
        packages: {
          "": { name: "my-app", version: "1.0.0" },
          "node_modules/react": { version: "18.2.0" },
          "node_modules/react-dom": { version: "18.2.0" },
          "node_modules/scheduler": { version: "0.23.0" },
        },
      });

      const deps = parseTransitiveDeps(lockfile);
      expect(deps.size).toBe(3);
      expect(deps.get("react")).toBe("18.2.0");
      expect(deps.get("scheduler")).toBe("0.23.0");
    });

    test("parses npm v1 lockfile dependencies", () => {
      const lockfile = JSON.stringify({
        dependencies: {
          react: {
            version: "18.2.0",
            dependencies: {
              "loose-envify": { version: "1.4.0" },
            },
          },
        },
      });

      const deps = parseTransitiveDeps(lockfile);
      expect(deps.size).toBe(2);
      expect(deps.get("react")).toBe("18.2.0");
    });

    test("handles malformed JSON", () => {
      const deps = parseTransitiveDeps("not json");
      expect(deps.size).toBe(0);
    });
  });
});
