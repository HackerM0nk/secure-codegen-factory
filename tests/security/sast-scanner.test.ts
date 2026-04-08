// tests/security/sast-scanner.test.ts
// Unit tests for the in-process SAST scanner

import { scanFiles } from "../../src/server/security/sast-scanner";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

describe("SAST Scanner", () => {
  describe("Injection Rules", () => {
    test("detects eval() with variable input", () => {
      const files = makeFiles({
        "src/app.ts": `const input = req.body.code;\neval(input);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "eval-with-variable")).toBe(true);
      expect(result.findings[0].cwe).toBe("CWE-95");
    });

    test("ignores eval with string literal", () => {
      const files = makeFiles({
        "src/app.ts": `eval("console.log('hello')");`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "eval-with-variable")).toBe(false);
    });

    test("detects new Function() constructor", () => {
      const files = makeFiles({
        "src/app.ts": `const fn = new Function(userInput);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "function-constructor")).toBe(true);
    });

    test("detects innerHTML assignment with variable", () => {
      const files = makeFiles({
        "src/app.tsx": `element.innerHTML = userInput;`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "innerhtml-assignment")).toBe(true);
      expect(result.findings[0].cwe).toBe("CWE-79");
    });

    test("detects dangerouslySetInnerHTML in JSX", () => {
      const files = makeFiles({
        "src/App.tsx": `<div dangerouslySetInnerHTML={{ __html: content }} />`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "dangerously-set-innerhtml")).toBe(true);
    });
  });

  describe("Command Injection Rules", () => {
    test("detects child_process.exec with variable", () => {
      const files = makeFiles({
        "src/run.ts": `exec(command);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "child-process-exec-variable")).toBe(true);
      expect(result.findings[0].cwe).toBe("CWE-78");
    });

    test("detects spawn with shell:true", () => {
      const files = makeFiles({
        "src/run.ts": `spawn("cmd", args, { shell: true });`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "shell-spawn-variable")).toBe(true);
    });
  });

  describe("SQL Injection Rules", () => {
    test("detects SQL with template literal interpolation", () => {
      const files = makeFiles({
        "src/db.ts": "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);",
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "sql-string-concat")).toBe(true);
      expect(result.findings[0].cwe).toBe("CWE-89");
    });

    test("detects SQL with string concatenation", () => {
      const files = makeFiles({
        "src/db.ts": `db.query("SELECT * FROM users WHERE name = '" + name);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "sql-string-plus")).toBe(true);
    });
  });

  describe("Path Traversal Rules", () => {
    test("detects path.join with req input", () => {
      const files = makeFiles({
        "src/files.ts": `const filePath = path.join("/uploads", req.params.filename);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "path-traversal-join")).toBe(true);
      expect(result.findings[0].cwe).toBe("CWE-22");
    });

    test("detects fs.readFile with variable path", () => {
      const files = makeFiles({
        "src/files.ts": `fs.readFile(filePath, callback);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "fs-read-variable")).toBe(true);
    });
  });

  describe("Hardcoded Credentials Rules", () => {
    test("detects hardcoded password", () => {
      const files = makeFiles({
        "src/config.ts": `const password = "SuperSecret123!";`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "hardcoded-password")).toBe(true);
    });

    test("detects hardcoded AWS access key", () => {
      const files = makeFiles({
        "src/config.ts": `const key = "AKIAIOSFODNN7EXAMPLE";`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "hardcoded-aws-key")).toBe(true);
    });

    test("detects embedded private key", () => {
      const files = makeFiles({
        "src/config.ts": `const key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpA...";`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "hardcoded-private-key")).toBe(true);
    });
  });

  describe("Insecure Crypto Rules", () => {
    test("detects MD5 usage", () => {
      const files = makeFiles({
        "src/hash.ts": `const hash = createHash("md5").update(data).digest("hex");`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "weak-hash-md5")).toBe(true);
    });

    test("detects SHA-1 usage", () => {
      const files = makeFiles({
        "src/hash.ts": `const hash = createHash("sha1").update(data).digest("hex");`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "weak-hash-sha1")).toBe(true);
    });

    test("detects Math.random for security", () => {
      const files = makeFiles({
        "src/token.ts": `const token = Math.random().toString(36);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "math-random-security")).toBe(true);
    });
  });

  describe("Other Rules", () => {
    test("detects SSRF via fetch with variable URL", () => {
      const files = makeFiles({
        "src/api.ts": `fetch(userUrl);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "ssrf-fetch-variable")).toBe(true);
    });

    test("detects prototype pollution", () => {
      const files = makeFiles({
        "src/util.ts": `obj[key] = value;`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "prototype-pollution")).toBe(true);
    });

    test("detects sensitive data logging", () => {
      const files = makeFiles({
        "src/auth.ts": `console.log("Auth token:", password);`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "log-sensitive-data")).toBe(true);
    });
  });

  describe("File Filtering", () => {
    test("skips node_modules", () => {
      const files = makeFiles({
        "node_modules/evil/index.js": `eval(userInput);`,
      });
      const result = scanFiles(files);
      expect(result.filesScanned).toBe(0);
      expect(result.findings).toHaveLength(0);
    });

    test("skips .git directory", () => {
      const files = makeFiles({
        ".git/hooks/pre-commit": `eval(something);`,
      });
      const result = scanFiles(files);
      expect(result.filesScanned).toBe(0);
    });

    test("respects filePattern on rules", () => {
      // dangerously-set-innerhtml only applies to .tsx/.jsx
      const files = makeFiles({
        "src/util.ts": `dangerouslySetInnerHTML={{ __html: x }}`,
      });
      const result = scanFiles(files);
      expect(result.findings.some((f) => f.rule === "dangerously-set-innerhtml")).toBe(false);
    });
  });

  describe("Result Structure", () => {
    test("findings are sorted by severity", () => {
      const files = makeFiles({
        "src/app.ts": [
          `eval(userInput);`,                         // critical
          `element.innerHTML = data;`,                // high
          `const h = createHash("md5").update("x");`, // medium
        ].join("\n"),
      });
      const result = scanFiles(files);
      const severities = result.findings.map((f) => f.severity);
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < severities.length; i++) {
        expect(order[severities[i]]).toBeGreaterThanOrEqual(order[severities[i - 1]]);
      }
    });

    test("pass/fail based on severity threshold", () => {
      const files = makeFiles({
        "src/app.ts": `eval(userInput);`,
      });
      // Default threshold is "critical" — should fail
      const result = scanFiles(files);
      expect(result.passed).toBe(false);

      // With "low" threshold — everything fails
      const resultLow = scanFiles(files, { severityThreshold: "low" });
      expect(resultLow.passed).toBe(false);
    });

    test("clean files pass", () => {
      const files = makeFiles({
        "src/app.ts": `
          import express from "express";
          const app = express();
          app.get("/", (req, res) => res.json({ ok: true }));
          app.listen(3000);
        `,
      });
      const result = scanFiles(files);
      expect(result.passed).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    test("reports correct line numbers", () => {
      const files = makeFiles({
        "src/app.ts": `line1\nline2\neval(userInput);\nline4`,
      });
      const result = scanFiles(files);
      const finding = result.findings.find((f) => f.rule === "eval-with-variable");
      expect(finding?.line).toBe(3);
    });
  });
});
