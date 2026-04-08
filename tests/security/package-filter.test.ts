// tests/security/package-filter.test.ts
// Unit tests for package installation security gate
// Note: Tests that hit npm registry are mocked to avoid network dependency

import { filterPackageInstall } from "../../src/server/security/package-filter";

// Mock global fetch for registry calls
const originalFetch = global.fetch;

beforeEach(() => {
  // Default mock: package exists, old enough, popular
  global.fetch = jest.fn().mockImplementation((url: string) => {
    if (url.includes("registry.npmjs.org")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            time: { created: "2020-01-01T00:00:00.000Z" },
          }),
      });
    }
    if (url.includes("api.npmjs.org/downloads")) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ downloads: 100000 }),
      });
    }
    return Promise.resolve({ ok: false, status: 404 });
  });
});

afterAll(() => {
  global.fetch = originalFetch;
});

describe("Package Filter", () => {
  describe("Known malicious packages — exact match", () => {
    test.each([
      "crossenv",
      "cross-env.js",
      "mongose",
      "mysqljs",
      "node-fabric",
      "nodemailer-js",
      "shadowsock",
      "sqlite.js",
    ])("blocks known malicious: npm install %s", async (pkg) => {
      const result = await filterPackageInstall(`npm install ${pkg}`);
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("known_malicious");
    });
  });

  describe("Known malicious packages — pattern match", () => {
    test("blocks packages matching malicious patterns", async () => {
      const result = await filterPackageInstall("npm install @evildomain/pkg");
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("malicious_pattern");
    });

    test("blocks -malware suffix", async () => {
      const result = await filterPackageInstall("npm install react-malware");
      expect(result.allowed).toBe(false);
    });
  });

  describe("Typosquatting detection", () => {
    test.each([
      ["reacr", "react"],       // 1 char off from react
      ["exprss", "express"],    // 1 char off from express
    ])("blocks typosquat %s (similar to %s)", async (typo, real) => {
      const result = await filterPackageInstall(`npm install ${typo}`);
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("typosquatting");
      expect(result.blockedPackages[0].details).toContain(real);
    });

    test("allows actual popular packages", async () => {
      const result = await filterPackageInstall("npm install react");
      expect(result.allowed).toBe(true);
    });
  });

  describe("Package age check", () => {
    test("blocks packages younger than 7 days", async () => {
      const yesterday = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString();
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes("registry.npmjs.org")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ time: { created: yesterday } }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ downloads: 100000 }),
        });
      });

      const result = await filterPackageInstall("npm install brand-new-pkg");
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("too_new");
    });

    test("blocks packages not found on registry", async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes("registry.npmjs.org")) {
          return Promise.resolve({ ok: false, status: 404 });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ downloads: 0 }),
        });
      });

      const result = await filterPackageInstall("npm install nonexistent-pkg-xyz");
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("not_found");
    });
  });

  describe("Popularity check", () => {
    test("blocks packages with very low downloads", async () => {
      (global.fetch as jest.Mock).mockImplementation((url: string) => {
        if (url.includes("registry.npmjs.org")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () =>
              Promise.resolve({ time: { created: "2020-01-01T00:00:00.000Z" } }),
          });
        }
        if (url.includes("api.npmjs.org/downloads")) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ downloads: 10 }),
          });
        }
        return Promise.resolve({ ok: false, status: 404 });
      });

      const result = await filterPackageInstall("npm install obscure-tiny-pkg");
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages[0].reason).toBe("low_popularity");
    });
  });

  describe("Command parsing", () => {
    test("parses npm install with multiple packages", async () => {
      const result = await filterPackageInstall("npm install react react-dom");
      expect(result.allowed).toBe(true);
    });

    test("parses yarn add", async () => {
      const result = await filterPackageInstall("yarn add crossenv");
      expect(result.allowed).toBe(false);
    });

    test("parses pnpm add", async () => {
      const result = await filterPackageInstall("pnpm add crossenv");
      expect(result.allowed).toBe(false);
    });

    test("ignores flags", async () => {
      const result = await filterPackageInstall("npm install --save-dev react");
      expect(result.allowed).toBe(true);
    });

    test("strips version specifiers", async () => {
      const result = await filterPackageInstall("npm install crossenv@1.0.0");
      expect(result.allowed).toBe(false);
    });

    test("handles empty command", async () => {
      const result = await filterPackageInstall("npm install");
      expect(result.allowed).toBe(true);
      expect(result.blockedPackages).toHaveLength(0);
    });
  });

  describe("Multiple packages", () => {
    test("blocks all malicious packages in a batch", async () => {
      const result = await filterPackageInstall("npm install crossenv mongose");
      expect(result.allowed).toBe(false);
      expect(result.blockedPackages).toHaveLength(2);
    });
  });
});
