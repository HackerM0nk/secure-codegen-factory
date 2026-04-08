# Contributing to secure-codegen-factory

Thank you for your interest in contributing. This project takes a security-first approach to AI code generation — contributions that strengthen the defense-in-depth model are especially welcome.

## Getting Started

```bash
# Clone and bootstrap
git clone https://github.com/hackerm0nk/secure-codegen-factory.git
cd secure-codegen-factory
./scripts/bootstrap.sh
```

This installs dependencies, starts infrastructure (Docker Compose), pushes the database schema, and builds the workspace image. See [README.md](README.md) for full prerequisites.

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Run the test suites before submitting:

```bash
npm test                          # 262 unit tests
npm run test:security:regression  # 48-vector attack regression
npm run test:security:pipeline    # 9-step E2E security pipeline
npm run build                     # Verify clean build
```

4. Open a pull request with a clear description of what changed and why

## Running Tests

| Command | What it does |
|---------|-------------|
| `npm test` | Unit tests (Jest) |
| `npm run test:security:regression` | 48-vector attack suite against all security layers |
| `npm run test:security:pipeline` | Full E2E pipeline: API -> SIEM -> Prometheus -> Loki |
| `npm run test:security:model-regression` | Compare security behavior across LLM models |
| `npm run test:e2e` | Playwright browser tests |

## Security Contributions

Security improvements are the highest-value contributions. If you want to:

- **Add a new security layer**: Implement it in `src/server/security/`, wire it into the agent loop (`src/server/services/agent-loop.ts`), add SIEM detection rules, and add regression test vectors.
- **Add attack vectors**: Add entries to `tests/e2e-security/vectors/` with the attack payload, expected blocked layer, and MITRE ATT&CK mapping.
- **Improve detection rules**: Rules live in `src/server/security/siem-rules-engine.ts`. Each rule needs a unique ID (100xxx), severity, MITRE mapping, and correlation window if applicable.

Every security claim must be backed by a test. If you add a layer, add the vectors that prove it works.

## Code Style

- TypeScript throughout (strict mode)
- Structured JSON logging via Pino — no `console.log`
- Security events flow through Redis Streams — don't bypass the event bus
- MITRE ATT&CK and CWE mappings on all security controls
- Correlation IDs propagated on all requests

## What NOT to Submit

- PRs that bypass or weaken security layers for convenience
- Dependencies without justification (we gate on package age and download count)
- `console.log` statements — use the structured logger
- Changes to `.env` or credentials of any kind
- Features that don't include tests

## Reporting Security Issues

If you discover a security vulnerability, **do not open a public issue**. Instead, email the maintainer directly. We take security reports seriously and will respond within 48 hours.

## Questions?

Open a discussion or issue on GitHub. We're happy to help you find the right place to contribute.
