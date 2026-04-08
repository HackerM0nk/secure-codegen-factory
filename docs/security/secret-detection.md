# Secret Detection

> Two complementary modules: `secret-detector.ts` for real-time input/output
> sanitization and `secret-scanner.ts` for bulk file scanning. Both use
> pattern matching and Shannon entropy analysis.

## Architecture

| Module | Purpose | Input | When It Runs |
|---|---|---|---|
| `secret-detector.ts` | Sanitize user messages and agent output | Single string | Every user message (Layer 1), every `file_write` |
| `secret-scanner.ts` | Scan workspace files for leaked secrets | Map of file paths to contents | Pre-deploy security scan (Layer 11) |

## secret-detector.ts: Real-Time Sanitization

### Pattern-Based Detection (12 Patterns)

| Pattern Name | Type | Regex | Example Match |
|---|---|---|---|
| `aws_access_key` | AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | AWS Secret Key | `aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}` | `aws_secret_access_key = wJal...` |
| `anthropic_api_key` | Anthropic API Key | `sk-ant-api\d{2}-[A-Za-z0-9\-_]{86}` | `sk-ant-api03-...` |
| `openai_api_key` | OpenAI API Key | `sk-(?!ant-)[A-Za-z0-9]{48,}` | `sk-proj-...` |
| `github_pat` | GitHub PAT | `ghp_[A-Za-z0-9]{36}` | `ghp_xxxxxxxxxxxx...` |
| `github_pat_fine` | GitHub Fine-Grained PAT | `github_pat_[A-Za-z0-9_]{82}` | `github_pat_11A...` |
| `stripe_secret_live` | Stripe Live Secret | `sk_live_[A-Za-z0-9]{24,}` | `sk_live_...` |
| `stripe_secret_test` | Stripe Test Secret | `sk_test_[A-Za-z0-9]{24,}` | `sk_test_...` |
| `stripe_pub_live` | Stripe Live Publishable | `pk_live_[A-Za-z0-9]{24,}` | `pk_live_...` |
| `stripe_pub_test` | Stripe Test Publishable | `pk_test_[A-Za-z0-9]{24,}` | `pk_test_...` |
| `private_key_pem` | Private Key (PEM) | `-----BEGIN ... PRIVATE KEY-----` | `-----BEGIN RSA PRIVATE KEY-----` |
| `slack_token` | Slack Token | `xox[bpras]-[0-9]{10,13}-...` | `xoxb-123456789-...` |
| `sendgrid_key` | SendGrid API Key | `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}` | `SG.xxxxxxx...` |

### Entropy-Based Detection

Tokens of 20+ alphanumeric characters with Shannon entropy > 4.5 bits/char
are flagged as `high_entropy_token`. UUIDs and kebab-case paths are excluded
as false positives.

### Sanitization Behavior

Detected secrets are replaced with `[REDACTED_SECRET_N]` placeholders in
the sanitized output. The original values are stored as masked versions
(first 4 + `****` + last 4 characters). If a Redis client is configured,
detection metadata is stored with a 24-hour TTL under `secret:{hash}` keys.

## secret-scanner.ts: Bulk File Scanning

### Pattern-Based Detection (19 Patterns)

| ID | Type | Severity | Regex |
|---|---|---|---|
| `aws-access-key` | AWS Access Key | critical | `AKIA[0-9A-Z]{16}` |
| `aws-secret-key` | AWS Secret Key | critical | `aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}` |
| `github-pat` | GitHub PAT | critical | `ghp_[A-Za-z0-9]{36,}` |
| `github-pat-fine` | GitHub Fine-Grained PAT | critical | `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` |
| `github-oauth` | GitHub OAuth | critical | `gho_[A-Za-z0-9]{36,}` |
| `anthropic-key` | Anthropic API Key | critical | `sk-ant-api[A-Za-z0-9-]{20,}` |
| `openai-key` | OpenAI API Key | critical | `sk-[A-Za-z0-9]{48,}` |
| `stripe-live-secret` | Stripe Live Secret | critical | `sk_live_[A-Za-z0-9]{24,}` |
| `stripe-live-publish` | Stripe Live Publishable | high | `pk_live_[A-Za-z0-9]{24,}` |
| `slack-webhook` | Slack Webhook URL | high | `https://hooks.slack.com/services/T.../B.../...` |
| `slack-token` | Slack Token | critical | `xox[bpors]-[A-Za-z0-9-]{10,}` |
| `sendgrid-key` | SendGrid API Key | critical | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` |
| `private-key-rsa` | RSA Private Key | critical | `-----BEGIN RSA PRIVATE KEY-----` |
| `private-key-ec` | EC Private Key | critical | `-----BEGIN EC PRIVATE KEY-----` |
| `private-key-openssh` | OpenSSH Private Key | critical | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| `private-key-generic` | Private Key (generic) | critical | `-----BEGIN PRIVATE KEY-----` |
| `database-url` | Database Connection String | high | `postgres://user:pass@host` |
| `jwt-token` | JWT Token | medium | `eyJ...eyJ...` (3-part base64) |
| `google-api-key` | Google API Key | high | `AIza[A-Za-z0-9_-]{35}` |

### Entropy-Based Detection (File Mode)

The file scanner checks quoted strings and assignment values (20+
characters) for Shannon entropy > 4.5 bits/char with minimum length 24.
Excluded patterns: MongoDB ObjectIDs, UUIDs, URLs/paths, ALL_CAPS constants.

### Skipped Paths

| Skip Type | Values |
|---|---|
| Directories | `node_modules`, `.git`, `dist`, `build`, `.next`, `coverage`, `__pycache__`, `.devfactory` |
| Files | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Extensions | `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.zip`, `.gz`, `.tar`, `.br`, `.mp3`, `.mp4`, `.webm`, `.ogg`, `.wasm`, `.map` |

### Pass/Fail Logic

The scan **fails** (passed = false) if any finding has `critical` severity.

## Related Docs

- [Input Firewall](input-firewall.md) -- Secret detection runs before the
  firewall in the SecurityLayer pipeline
- [Code Scanning](code-scanning.md) -- The secret scanner is one component
  of the full security scan
- [Security Overview](README.md) -- Layer 1 (real-time) and Layer 11
  (bulk scanning)
