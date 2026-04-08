# Security Testing

The test suite validates the defense-in-depth security stack against a comprehensive attack taxonomy. Tests run at three levels: unit tests for individual security layers, regression tests against the full attack vector library, and end-to-end pipeline tests that verify event flow across SIEM, Prometheus, and Loki.

Source files:
- `tests/e2e-security/attack-vectors.ts` -- 56-vector attack taxonomy
- `tests/e2e-security/harness.ts` -- regression test runner (unit + E2E modes)
- `tests/e2e-security/full-pipeline-test.ts` -- 9-scenario pipeline test
- `tests/e2e-security/model-regression.ts` -- model onboarding regression
- `tests/security/*.test.ts` -- 10 Jest unit test files for individual security layers

## Attack Vector Taxonomy

The `ATTACK_VECTORS` array in `attack-vectors.ts` defines 56 test vectors across 20 threat categories. Each vector specifies a malicious prompt, expected detection layers, pass criteria, MITRE ATT&CK / CWE / OWASP LLM mappings, and severity.

### Vectors by Category

| Category | Count | IDs | Severity Range |
|----------|-------|-----|---------------|
| PROMPT_INJECTION | 8 | PI-001 through PI-008 | medium to critical |
| JAILBREAK | 3 | JB-001 through JB-003 | high to critical |
| SYSTEM_PROMPT_EXTRACTION | 4 | SPE-001 through SPE-004 | medium to critical |
| REVERSE_SHELL | 6 | RS-001 through RS-006 | critical |
| CONTAINER_ESCAPE | 4 | CE-001 through CE-004 | critical |
| DESTRUCTIVE_COMMAND | 3 | DC-001 through DC-003 | critical |
| DATA_EXFILTRATION | 2 | DE-001, DE-002 | high to critical |
| CREDENTIAL_THEFT | 5 | CT-001 through CT-005 | critical |
| TYPOSQUATTING | 2 | SC-001, SC-003 | high |
| SUPPLY_CHAIN | 2 | SC-002, SC-004 | low to critical |
| SSRF | 2 | SSRF-001, SSRF-002 | critical |
| CRYPTO_MINING | 1 | CM-001 | critical |
| DDOS_TOOL | 1 | DD-001 | critical |
| MULTI_TURN_ESCALATION | 1 | MT-001 | high |
| SOCIAL_ENGINEERING | 2 | SE-001, SE-002 | high |
| VULNERABLE_CODE | 4 | VC-001 through VC-004 | high to critical |
| K8S_ESCAPE | 1 | K8-001 | critical |
| PRIVILEGE_ESCALATION | 2 | PE-001, PE-002 | medium to critical |
| INDIRECT_INJECTION | 1 | PI-004 | high |
| Negative tests | 3 | NEG-001 through NEG-003 | low |

### Vectors by Severity

| Severity | Count |
|----------|-------|
| critical | 34 |
| high | 13 |
| medium | 3 |
| low | 6 |

### Test Modes

Each vector has a mode that determines when it runs:
- `unit` -- tests a security endpoint directly (fast, no LLM needed)
- `e2e` -- sends prompts through the full agent pipeline (requires LLM + workspace)
- `both` -- tests both paths

### Security Layers Tested

| Layer | Description | Vectors Targeting It |
|-------|-------------|---------------------|
| `input_firewall` | Regex + heuristic scoring | PI-001 through PI-007, SPE-001 |
| `injection_detector` | OWASP LLM Top 10 deep analysis | PI-003 through PI-008, JB-001 through JB-003, SPE-002 through SPE-004 |
| `intent_classifier` | Semantic intent detection | PI-002, JB-003, CM-001, DD-001, SE-001, SE-002, DE-001, DE-002 |
| `output_filter` | Post-LLM command denylist | RS-001 through RS-006, CE-001 through CE-004, DC-001 through DC-003, CT-001, CT-002, SSRF-001, SSRF-002, PE-001 |
| `package_filter` | Typosquat + malware blocking | SC-001 through SC-004 |
| `secret_detector` | Credential pattern matching | CT-003 through CT-005 |
| `trajectory_monitor` | Multi-turn behavioral scoring | MT-001 |
| `sast_scanner` | Static analysis of generated code | VC-001 through VC-004 |
| `network_cilium` | FQDN egress + metadata SSRF block | RS-001 through RS-003, SSRF-001, DE-001, DE-002 |
| `runtime_tetragon` | eBPF process/file/network monitoring | CE-001 through CE-004, CT-001, CT-002 |

## Regression Test Harness (`harness.ts`)

The main regression runner that executes attack vectors against the running backend.

### Usage

```bash
# Run all unit-mode tests (default)
npm run test:security:regression

# Run with verbose output
npm run test:security:regression:verbose

# Run E2E tests (requires LLM + workspace)
npm run test:security:e2e

# Filter by category
npx tsx tests/e2e-security/harness.ts --category=REVERSE_SHELL

# Filter by specific vector IDs
npx tsx tests/e2e-security/harness.ts --id=PI-001,RS-001

# Specify model for E2E tests
npx tsx tests/e2e-security/harness.ts --mode=e2e --model=dolphin-mistral:7b

# Generate JSON report
npx tsx tests/e2e-security/harness.ts --report
```

### Unit Test Flow

1. Map the vector's `unitEndpoint` to an API path:
   - `test-input` -> `POST /api/security/test-input`
   - `test-command` -> `POST /api/security/test-command`
   - `test-package` -> `POST /api/security/test-package`
   - `test-injection` -> `POST /api/security/test-injection`
   - `classify-intent` -> `POST /api/security/classify-intent`
2. Send the `unitPayload` to the endpoint
3. Evaluate `unitPassCriteria` against the response (operators: `equals`, `contains`, `truthy`, `gte`, `oneOf`)
4. Infer which security layers detected the attack from response fields
5. Compare detected layers against expected layers

### E2E Test Flow

1. Send the vector's prompt to `POST /api/agent/<projectId>/message`
2. Parse the SSE response stream for security events
3. Identify which layers triggered (`security_block`, `error`, `tool_result` with blocked flag)
4. Compare against expected detection layers

### Report Output

The harness generates a report containing:
- **Summary**: total/passed/failed/pass rate/duration
- **Layer coverage**: per-layer catch rate (tested vs caught)
- **Category coverage**: per-category pass/fail counts
- **Gaps**: failed vectors with missed layers (action items)
- **Recommendations**: auto-generated based on failures

Reports are saved as JSON to `tests/e2e-security/reports/`.

## Full Pipeline Test (`full-pipeline-test.ts`)

Tests the complete event flow from security API through SIEM, Prometheus, and Loki.

### Usage

```bash
npm run test:security:pipeline
npm run test:security:pipeline:report   # with JSON report
```

### Test Scenarios (9 attacks)

| ID | Attack | Endpoint | Expected Layer | SIEM Rule |
|----|--------|----------|---------------|-----------|
| E2E-INJ-001 | Direct prompt injection | test-input | input_firewall | 100001 |
| E2E-CMD-001 | Reverse shell | test-command | output_filter | 100002 |
| E2E-CMD-002 | Container escape (nsenter) | test-command | output_filter | 100002 |
| E2E-PKG-001 | Typosquatting (crossenv) | test-package | package_filter | -- |
| E2E-INJ-002 | DAN jailbreak injection | test-injection | injection_detector | 100020 |
| E2E-INT-001 | Crypto mining intent | classify-intent | intent_classifier | 100022 |
| E2E-SEC-001 | AWS key in input | test-input | secret_detector | 100003 |
| E2E-CMD-003 | Destructive rm -rf | test-command | output_filter | 100002 |
| E2E-NEG-001 | Legitimate npm install | test-package | (none, should pass) | -- |

### Verification Steps

For each test, the pipeline verifies:
1. **Security API**: correct block/allow response
2. **SIEM Engine**: expected rule fired (checked via `GET /api/security/siem/alerts`)
3. **Prometheus**: `security_blocks_total` metric increased
4. **Audit Log**: entries logged (via SIEM stats proxy)

Post-test checks verify:
- Prometheus block count delta
- SIEM total alerts and by-level distribution
- Loki log streams containing "security"
- Grafana health

### Pre-flight Checks

The test validates connectivity to the backend API, Prometheus (`localhost:9190`), and Loki (`localhost:3200`) before running.

## Model Regression Testing (`model-regression.ts`)

Tests whether the security stack works regardless of which LLM model is configured.

### Usage

```bash
# Auto-discover models from Ollama
npm run test:security:model-regression

# Specify models
npx tsx tests/e2e-security/model-regression.ts --models=dolphin-mistral:7b,qwen3:0.6b
```

### How It Works

1. Discover available models from Ollama (`http://localhost:11434/api/tags`) or accept `--models` CLI argument
2. Run the full unit test suite (all vectors with `mode: unit` or `mode: both`)
3. Generate a baseline result (security layers are model-agnostic for unit tests)
4. Produce a per-model compliance risk assessment:
   - Models containing `dolphin`, `uncensored`, `wizard-vicuna`, `nous-hermes`, or `abliterated` are flagged as HIGH risk
   - Other models are flagged as LOW risk
5. Verdict: PASS if all security layers caught all attacks; FAIL with remediation instructions if any gaps

### Report

JSON reports are saved to `tests/e2e-security/reports/model-regression-<timestamp>.json`.

## Current Test Results

As of the latest run:

### Unit Tests
- **262 tests** across **10 suites** -- all passing

### Regression Vectors
- **48/48 vectors** passing (100% pass rate) across **15 attack categories**

### E2E Pipeline Tests
- **9/9 scenarios** passing (100% pass rate) with **6 security layers activated**

### Layer Coverage

| Layer | Coverage |
|-------|----------|
| secret_detector | 100% |
| package_filter | 100% |
| intent_classifier | 88% |
| output_filter | 86% |
| input_firewall | 67% |
| injection_detector | 57% |
| network_cilium | 0% (infrastructure-layer, not testable in local Docker) |
| runtime_tetragon | 0% (infrastructure-layer, not testable in local Docker) |

The `network_cilium` and `runtime_tetragon` layers require Kubernetes with eBPF support and are validated in cluster deployments, not in the local Docker test environment.

## Jest Unit Tests (`tests/security/`)

Ten test files cover individual security layers with focused unit tests:

| File | Layer Tested |
|------|-------------|
| `input-firewall.test.ts` | Input firewall regex and scoring |
| `prompt-injection-detector.test.ts` | OWASP LLM Top 10 injection detection |
| `output-filter.test.ts` | Post-LLM command filtering |
| `package-filter.test.ts` | Typosquat and malware package blocking |
| `secret-scanner.test.ts` | Credential pattern matching |
| `sast-scanner.test.ts` | Static analysis patterns |
| `sca-scanner.test.ts` | npm audit integration |
| `sbom-generator.test.ts` | Software bill of materials |
| `security-layer.test.ts` | Integrated security layer orchestration |
| `trajectory-monitor.test.ts` | Multi-turn risk scoring |

### Running Unit Tests

```bash
# All unit tests
npm test

# Security tests only
npm run test:security

# With coverage
npm run test:coverage
```

## npm Script Reference

| Script | Command | Description |
|--------|---------|-------------|
| `test` | `npx jest` | All Jest unit tests |
| `test:security` | `npx jest tests/security/` | Security unit tests only |
| `test:coverage` | `npx jest --coverage` | Unit tests with coverage report |
| `test:security:regression` | `npx tsx tests/e2e-security/harness.ts --report` | 56-vector regression suite |
| `test:security:regression:verbose` | same + `--verbose` | Verbose regression output |
| `test:security:e2e` | harness with `--mode=e2e --report` | E2E regression (requires LLM) |
| `test:security:model-regression` | `npx tsx tests/e2e-security/model-regression.ts` | Model onboarding regression |
| `test:security:pipeline` | `npx tsx tests/e2e-security/full-pipeline-test.ts` | 9-attack pipeline test |
| `test:security:pipeline:report` | same + `--report` | Pipeline test with JSON report |

## Related Documentation

- [Event System](../architecture/event-system.md) -- events verified by the pipeline test
- [Observability](../observability/README.md) -- Prometheus metrics and alert rules tested
- [Architecture Overview](../architecture/README.md) -- system context for security layers
