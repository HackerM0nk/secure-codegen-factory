# Code Scanning

> Unified security scanner that orchestrates SAST, SCA, secrets, SBOM,
> and container image scanning. Implemented across `scanner.ts`,
> `sast-scanner.ts`, `sca-scanner.ts`, `secret-scanner.ts`, and
> `image-scanner.ts`.

## Architecture

The `scanWorkspace()` function in `scanner.ts` orchestrates all scan types
in parallel and aggregates findings into a unified verdict.

| Scanner | File | Method | What It Checks |
|---|---|---|---|
| SAST | `sast-scanner.ts` | Pattern matching | Source code vulnerabilities |
| SCA | `sca-scanner.ts` | `npm audit --json` | Known dependency vulnerabilities |
| Secrets | `secret-scanner.ts` | Pattern + entropy | Leaked credentials in files |
| SBOM | `sbom-generator.ts` | Package.json parsing | Software bill of materials |
| Image | `image-scanner.ts` | Trivy | Container image CVEs |

## Unified Verdict Logic

| Condition | Verdict | Effect |
|---|---|---|
| Any critical finding (any scanner) | BLOCK | Deployment blocked |
| Any high finding (no criticals) | WARN | Deployment allowed with warning |
| No critical or high findings | PASS | Clean deployment |

The `passed` flag is `false` if any critical finding exists across all
scanners.

## SAST Scanner (24 Rules)

The SAST scanner applies regex-based rules to source files, similar to
Semgrep. Each rule targets specific file types and CWE categories.

### Injection Rules

| Rule ID | Severity | CWE | File Types | What It Detects |
|---|---|---|---|---|
| `eval-with-variable` | critical | CWE-95 | ts/js | `eval()` called with dynamic input |
| `function-constructor` | critical | CWE-95 | ts/js | `new Function()` (equivalent to eval) |
| `innerhtml-assignment` | high | CWE-79 | ts/js | `.innerHTML = ` (XSS) |
| `dangerously-set-innerhtml` | high | CWE-79 | tsx/jsx | `dangerouslySetInnerHTML` (React XSS) |
| `document-write` | high | CWE-79 | ts/js | `document.write()` (XSS) |

### Command Injection Rules

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `child-process-exec-variable` | critical | CWE-78 | `exec()`/`execSync()` with dynamic input |
| `shell-spawn-variable` | high | CWE-78 | `spawn()`/`execFile()` with `shell: true` |

### SQL Injection Rules

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `sql-string-concat` | critical | CWE-89 | SQL with template literal interpolation `${...}` |
| `sql-string-plus` | high | CWE-89 | SQL built with `+` string concatenation |

### Path Traversal Rules

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `path-traversal-join` | high | CWE-22 | `path.join()` with `req.params`/`req.query` |
| `fs-read-variable` | medium | CWE-22 | `fs.readFile()` with dynamic path |

### Hardcoded Credentials

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `hardcoded-password` | high | CWE-798 | `password = "..."`, `secret = "..."`, etc. |
| `hardcoded-aws-key` | critical | CWE-798 | `AKIA...` AWS access key in source |
| `hardcoded-private-key` | critical | CWE-321 | PEM private key in source |

### Insecure Crypto

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `weak-hash-md5` | medium | CWE-328 | `createHash('md5')` |
| `weak-hash-sha1` | medium | CWE-328 | `createHash('sha1')` |
| `math-random-security` | medium | CWE-338 | `Math.random()` |

### Other Rules

| Rule ID | Severity | CWE | What It Detects |
|---|---|---|---|
| `json-parse-unvalidated` | medium | CWE-502 | `JSON.parse(req.body)` without schema |
| `prototype-pollution` | high | CWE-1321 | Dynamic property assignment `[key] = ` |
| `ssrf-fetch-variable` | high | CWE-918 | `fetch()` with dynamic URL |
| `log-sensitive-data` | medium | CWE-532 | Logging password/token/secret |

## SCA Scanner

Parses the output of `npm audit --json` into structured vulnerability
records. Supports both npm v7+ format (`audit.vulnerabilities` object) and
npm v6 format (`audit.advisories` object).

Each vulnerability includes:
- Package name, severity, title, advisory URL
- Affected version range
- Whether a fix is available
- CVSS score and CWE IDs (when available)
- Whether it is a direct dependency

**Pass/fail**: The scan fails if any `critical` vulnerability exists.

## Image Scanner (Trivy)

Scans container images using Trivy (`trivy image --format json`). Requires
Trivy to be installed on the host.

| Parameter | Value |
|---|---|
| Severity filter | CRITICAL, HIGH, MEDIUM, LOW |
| Timeout | 120 seconds |
| Max buffer | 10 MB |
| Cache TTL | 10 minutes |
| Pass/fail | Fails on any CRITICAL finding |

If Trivy is not installed, the scan returns a PASS with an error message.
Image scanning is **opt-in** (disabled by default in `ScanOptions`).

## Scan Orchestration

The `scanWorkspace()` function:

1. Collects all source files from the workspace container (up to 300
   files, <500KB each, excluding node_modules/.git/dist/.next)
2. Runs SAST, SCA, secrets, SBOM, and image scans in parallel
3. Aggregates finding counts by severity across all scanners
4. Computes unified verdict (BLOCK/WARN/PASS)

The `scanPlatform()` function runs the same SAST and secrets scans against
the DevFactory platform's own source code (self-scan).

## Skipped Paths

All scanners share a common skip list:

| Category | Skipped |
|---|---|
| Directories | node_modules, .git, dist, build, .next, .devfactory, coverage, __pycache__ |
| Files | package-lock.json, yarn.lock, pnpm-lock.yaml |

## Related Docs

- [Secret Detection](secret-detection.md) -- The secret scanner component
  in detail
- [Package Filter](package-filter.md) -- Pre-installation checks that
  complement post-install SCA
- [Security Overview](README.md) -- Layer 11 in the defense-in-depth stack
