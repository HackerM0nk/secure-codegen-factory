// src/server/security/package-filter.ts
// Package installation security gate with age, popularity, typosquatting, and blocklist checks

export interface BlockedPackage {
  name: string;
  reason: string;
  details: string;
}

export interface PackageFilterResult {
  allowed: boolean;
  blockedPackages: BlockedPackage[];
  reason?: string;
}

// ── TTL cache ───────────────────────────────────────────────────────────────

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

class TTLCache<T> {
  private store = new Map<string, CacheEntry<T>>();
  constructor(private defaultTTLMs: number = 600_000) {}

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T, ttlMs?: number): void {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + (ttlMs ?? this.defaultTTLMs),
    });
  }

  clear(): void {
    this.store.clear();
  }
}

const registryCache = new TTLCache<any>(600_000);
const downloadsCache = new TTLCache<number>(300_000);

// ── Known malicious package patterns ────────────────────────────────────────

const MALICIOUS_PATTERNS: RegExp[] = [
  /^@evildomain\//,
  /^crossenv$/,
  /^event-stream$/,
  /^flatmap-stream$/,
  /^coa$/,
  /^rc$/,
  /^ua-parser-js$/,
  /^colors$/,
  /^faker$/,
  /-malware$/,
  /^npm-script-/,
  /^node-hide-console-windows$/,
];

const MALICIOUS_EXACT = new Set([
  "crossenv", "cross-env.js", "crossenv.js",
  "d3.js", "gruntcli", "http-proxy.js",
  "jquery.js", "mariadb", "mongose",
  "mssql.js", "mssql-node", "mysqljs",
  "node-fabric", "node-opencv", "node-opensl",
  "node-openssl", "nodecaffe", "nodefabric",
  "nodeffmpeg", "nodemailer-js", "noderequest",
  "nodesass", "nodesqlite", "nodest",
  "shadowsock", "smb", "sqlite.js",
  "sqliter", "sqlserver", "tkinter",
]);

// ── Top npm packages for typosquatting detection ────────────────────────────

const TOP_PACKAGES = [
  "react", "react-dom", "next", "express", "lodash", "axios", "typescript",
  "webpack", "babel", "eslint", "prettier", "jest", "mocha", "chai",
  "moment", "dayjs", "date-fns", "uuid", "dotenv", "cors", "body-parser",
  "mongoose", "sequelize", "prisma", "knex", "pg", "mysql2", "redis",
  "socket.io", "graphql", "apollo", "fastify", "koa", "hapi", "nest",
  "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
  "chalk", "commander", "yargs", "inquirer", "ora", "debug", "winston",
  "nodemon", "concurrently", "cross-env", "rimraf", "glob", "fs-extra",
];

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function checkTyposquatting(pkg: string): string | null {
  if (TOP_PACKAGES.includes(pkg)) return null;
  for (const top of TOP_PACKAGES) {
    const dist = levenshteinDistance(pkg, top);
    if (dist > 0 && dist < 2) {
      return top;
    }
  }
  return null;
}

// ── npm registry queries ────────────────────────────────────────────────────

async function fetchRegistryMeta(
  pkg: string
): Promise<{ createdAt: Date | null; error?: string }> {
  const cached = registryCache.get(`meta:${pkg}`);
  if (cached) return cached;

  try {
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(pkg)}`,
      { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(5000) }
    );
    if (res.status === 404) {
      const result = { createdAt: null, error: "Package not found on npm registry" };
      registryCache.set(`meta:${pkg}`, result);
      return result;
    }
    if (!res.ok) {
      return { createdAt: null, error: `Registry returned ${res.status}` };
    }
    const data = await res.json();
    const created = data.time?.created ? new Date(data.time.created) : null;
    const result = { createdAt: created };
    registryCache.set(`meta:${pkg}`, result);
    return result;
  } catch (err: any) {
    return { createdAt: null, error: `Registry fetch failed: ${err.message}` };
  }
}

async function fetchWeeklyDownloads(
  pkg: string
): Promise<{ downloads: number | null; error?: string }> {
  const cached = downloadsCache.get(`dl:${pkg}`);
  if (cached !== undefined) return { downloads: cached };

  try {
    const res = await fetch(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkg)}`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) {
      return { downloads: null, error: `Downloads API returned ${res.status}` };
    }
    const data = await res.json();
    const dl = data.downloads ?? null;
    if (dl !== null) downloadsCache.set(`dl:${pkg}`, dl);
    return { downloads: dl };
  } catch (err: any) {
    return { downloads: null, error: `Downloads fetch failed: ${err.message}` };
  }
}

// ── Parse npm install command ───────────────────────────────────────────────

function parsePackageNames(command: string): string[] {
  const installMatch = command.match(
    /(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s+(.*)/i
  );
  if (!installMatch) return [];

  const argsStr = installMatch[1];
  const packages: string[] = [];
  const tokens = argsStr.split(/\s+/).filter(Boolean);
  for (const token of tokens) {
    if (token.startsWith("-")) continue;
    const atIndex = token.startsWith("@") ? token.indexOf("@", 1) : token.indexOf("@");
    const name = atIndex > 0 ? token.substring(0, atIndex) : token;
    if (name) packages.push(name);
  }
  return packages;
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function filterPackageInstall(
  command: string
): Promise<PackageFilterResult> {
  const packageNames = parsePackageNames(command);
  if (packageNames.length === 0) {
    return { allowed: true, blockedPackages: [] };
  }

  const blockedPackages: BlockedPackage[] = [];

  for (const pkg of packageNames) {
    // 1. Known malicious exact match
    if (MALICIOUS_EXACT.has(pkg)) {
      blockedPackages.push({
        name: pkg,
        reason: "known_malicious",
        details: "Package is on the known malicious packages blocklist",
      });
      continue;
    }

    // 2. Known malicious pattern match
    const maliciousPattern = MALICIOUS_PATTERNS.find((r) => r.test(pkg));
    if (maliciousPattern) {
      blockedPackages.push({
        name: pkg,
        reason: "malicious_pattern",
        details: `Matches malicious pattern: ${maliciousPattern.source}`,
      });
      continue;
    }

    // 3. Typosquatting check
    const typosquatTarget = checkTyposquatting(pkg);
    if (typosquatTarget) {
      blockedPackages.push({
        name: pkg,
        reason: "typosquatting",
        details: `Suspiciously similar to popular package "${typosquatTarget}" (Levenshtein distance < 2). Did you mean "${typosquatTarget}"?`,
      });
      continue;
    }

    // 4. Age check
    const meta = await fetchRegistryMeta(pkg);
    if (meta.createdAt) {
      const ageMs = Date.now() - meta.createdAt.getTime();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < 7) {
        blockedPackages.push({
          name: pkg,
          reason: "too_new",
          details: `Package was first published ${ageDays.toFixed(1)} days ago (minimum: 7 days)`,
        });
        continue;
      }
    } else if (meta.error?.includes("not found")) {
      blockedPackages.push({
        name: pkg,
        reason: "not_found",
        details: "Package does not exist on npm registry",
      });
      continue;
    }

    // 5. Popularity check
    const dlResult = await fetchWeeklyDownloads(pkg);
    if (dlResult.downloads !== null && dlResult.downloads < 50) {
      blockedPackages.push({
        name: pkg,
        reason: "low_popularity",
        details: `Only ${dlResult.downloads} weekly downloads (minimum: 50)`,
      });
      continue;
    }
  }

  return {
    allowed: blockedPackages.length === 0,
    blockedPackages,
    reason:
      blockedPackages.length > 0
        ? `Blocked packages: ${blockedPackages.map((b) => `${b.name} (${b.reason})`).join(", ")}`
        : undefined,
  };
}
