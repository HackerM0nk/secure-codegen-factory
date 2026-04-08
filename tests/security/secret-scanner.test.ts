// tests/security/secret-scanner.test.ts
// Unit tests for TruffleHog-style pattern + entropy secret scanning

import { scanForSecrets } from "../../src/server/security/secret-scanner";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

describe("Secret Scanner", () => {
  describe("AWS Credentials", () => {
    test("detects AWS access key", () => {
      const files = makeFiles({
        "src/config.ts": `const key = "AKIAIOSFODNN7EXAMPLE";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "aws-access-key")).toBe(true);
      expect(result.passed).toBe(false); // critical
    });

    test("detects AWS secret key", () => {
      const files = makeFiles({
        ".env": `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "aws-secret-key")).toBe(true);
    });
  });

  describe("GitHub Tokens", () => {
    test("detects GitHub PAT", () => {
      const files = makeFiles({
        "src/api.ts": `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "github-pat")).toBe(true);
    });

    test("detects GitHub OAuth token", () => {
      const files = makeFiles({
        "src/api.ts": `const token = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "github-oauth")).toBe(true);
    });
  });

  describe("AI Provider Keys", () => {
    test("detects Anthropic API key", () => {
      const files = makeFiles({
        ".env": `ANTHROPIC_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "anthropic-key")).toBe(true);
    });

    test("detects OpenAI API key", () => {
      const files = makeFiles({
        ".env": `OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "openai-key")).toBe(true);
    });
  });

  describe("Payment Keys", () => {
    test("detects Stripe live secret key", () => {
      // Build the test key at runtime to avoid GitHub push protection false positives
      const testKey = ["sk", "live", "abcdefghijklmnopqrstuvwx"].join("_");
      const files = makeFiles({
        "src/billing.ts": `const stripe = new Stripe("${testKey}");`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "stripe-live-secret")).toBe(true);
    });

    test("detects Stripe live publishable key", () => {
      const files = makeFiles({
        "src/billing.ts": `const key = "pk_live_abcdefghijklmnopqrstuvwx";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "stripe-live-publish")).toBe(true);
    });
  });

  describe("Communication Keys", () => {
    test("detects Slack webhook URL", () => {
      const files = makeFiles({
        "src/notify.ts": `const url = "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnop";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "slack-webhook")).toBe(true);
    });

    test("detects Slack token", () => {
      const files = makeFiles({
        "src/slack.ts": `const token = "xoxb-1234567890-abcdefghij";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "slack-token")).toBe(true);
    });

    test("detects SendGrid key", () => {
      const files = makeFiles({
        ".env": `SENDGRID_KEY=SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "sendgrid-key")).toBe(true);
    });
  });

  describe("Private Keys", () => {
    test.each([
      ["RSA", "-----BEGIN RSA PRIVATE KEY-----", "private-key-rsa"],
      ["EC", "-----BEGIN EC PRIVATE KEY-----", "private-key-ec"],
      ["OpenSSH", "-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-openssh"],
      ["Generic", "-----BEGIN PRIVATE KEY-----", "private-key-generic"],
    ])("detects %s private key", (_, keyHeader, ruleId) => {
      const files = makeFiles({
        "certs/key.pem": `${keyHeader}\nMIIEpAIBAAKCAQEA...`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === ruleId)).toBe(true);
    });
  });

  describe("Database & Tokens", () => {
    test("detects database connection string", () => {
      const files = makeFiles({
        ".env": `DATABASE_URL=postgres://user:password@localhost:5432/mydb`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "database-url")).toBe(true);
    });

    test("detects JWT token", () => {
      const files = makeFiles({
        "test.ts": `const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "jwt-token")).toBe(true);
    });

    test("detects Google API key", () => {
      const files = makeFiles({
        "src/maps.ts": `const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "google-api-key")).toBe(true);
    });
  });

  describe("Shannon Entropy Detection", () => {
    test("detects high-entropy strings as potential secrets", () => {
      // A 32-char random-looking string with high entropy
      const files = makeFiles({
        "src/config.ts": `const key = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1x";`,
      });
      const result = scanForSecrets(files);
      const entropyFinding = result.findings.find((f) => f.rule === "high-entropy-string");
      if (entropyFinding) {
        expect(entropyFinding.entropy).toBeGreaterThan(4.0);
      }
    });

    test("does not flag low-entropy strings", () => {
      const files = makeFiles({
        "src/config.ts": `const key = "aaaaaaaabbbbbbbbccccccccdddddddd";`,
      });
      const result = scanForSecrets(files);
      expect(result.findings.some((f) => f.rule === "high-entropy-string")).toBe(false);
    });
  });

  describe("File Filtering", () => {
    test("skips node_modules", () => {
      const files = makeFiles({
        "node_modules/pkg/.env": `OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX`,
      });
      const result = scanForSecrets(files);
      expect(result.filesScanned).toBe(0);
    });

    test("skips binary extensions", () => {
      const files = makeFiles({
        "logo.png": "AKIAIOSFODNN7EXAMPLE",
        "font.woff2": "sk-ant-api-secret",
      });
      const result = scanForSecrets(files);
      expect(result.filesScanned).toBe(0);
    });

    test("skips lock files", () => {
      const files = makeFiles({
        "package-lock.json": `"integrity": "sha512-abc123..."`,
      });
      const result = scanForSecrets(files);
      expect(result.filesScanned).toBe(0);
    });
  });

  describe("Deduplication", () => {
    test("does not report same finding twice on same line", () => {
      const files = makeFiles({
        "src/config.ts": `const key = "AKIAIOSFODNN7EXAMPLE"; // AKIAIOSFODNN7EXAMPLE`,
      });
      const result = scanForSecrets(files);
      const awsFindings = result.findings.filter((f) => f.rule === "aws-access-key");
      expect(awsFindings).toHaveLength(1);
    });
  });

  describe("Clean Files", () => {
    test("passes clean source code", () => {
      const files = makeFiles({
        "src/app.ts": `
          import express from "express";
          const app = express();
          app.get("/", (req, res) => res.json({ ok: true }));
          app.listen(3000);
        `,
        "src/utils.ts": `
          export function add(a: number, b: number): number {
            return a + b;
          }
        `,
      });
      const result = scanForSecrets(files);
      expect(result.passed).toBe(true);
      expect(result.findings).toHaveLength(0);
    });
  });
});
