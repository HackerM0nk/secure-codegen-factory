# Security Architecture

> AI Dev Factory v2 implements defense-in-depth security across 16 layers,
> from user input to kernel syscalls. Every layer operates independently --
> if one layer is bypassed, the next catches the attack.

## Defense-in-Depth Philosophy

The system assumes that **every layer will eventually be bypassed**. No single
regex, heuristic, or LLM classifier is sufficient against a determined attacker.
Instead, security is a stack of independent, overlapping controls:

- **Fail-closed**: Unknown or ambiguous signals block by default.
- **No single point of failure**: Input firewall, injection detector, intent
  classifier, and behavioral detector each run independently.
- **Kernel-level enforcement**: Even if all application layers are bypassed,
  eBPF (Tetragon) kills container escape attempts at the syscall level.
- **Continuous scoring**: Session risk accumulates across turns -- a slow
  escalation attack is detected by trajectory monitoring even if each
  individual message passes all filters.

## Layer Map

| # | Layer | Implementation | Doc |
|---|-------|---------------|-----|
| 1 | Secret Redaction | `secret-detector.ts` | [secret-detection.md](secret-detection.md) |
| 2 | Input Firewall (Tier 1 Regex) | `input-firewall.ts` | [input-firewall.md](input-firewall.md) |
| 3 | Input Firewall (Tier 2 Heuristic) | `input-firewall.ts` | [input-firewall.md](input-firewall.md) |
| 4 | Prompt Injection Detection | `prompt-injection-detector.ts` | [injection-detection.md](injection-detection.md) |
| 5 | Intent Classification | `intent-classifier.ts` | [intent-classification.md](intent-classification.md) |
| 6 | Hardened System Prompt | `system-prompt.ts` | [injection-detection.md](injection-detection.md) |
| 7 | Output Command Filter | `output-filter.ts` | [output-filter.md](output-filter.md) |
| 8 | Package Installation Filter | `package-filter.ts` | [package-filter.md](package-filter.md) |
| 9 | Trajectory Monitoring | `trajectory-monitor.ts` | [behavioral-detection.md](behavioral-detection.md) |
| 10 | Behavioral Detection (LLM) | `behavioral-detector.ts` | [behavioral-detection.md](behavioral-detection.md) |
| 11 | Code Scanning (SAST/SCA/Secrets/Image) | `scanner.ts`, `sast-scanner.ts`, `sca-scanner.ts`, `image-scanner.ts`, `secret-scanner.ts` | [code-scanning.md](code-scanning.md) |
| 12 | SIEM Rules Engine | `siem-rules-engine.ts` | [siem-engine.md](siem-engine.md) |
| 13 | Incident Response | `incident-response.ts`, `runtime-correlator.ts` | [incident-response.md](incident-response.md) |
| 14 | Kubernetes Network Policies | `k8s/network-policies.yaml`, `k8s/cilium/network-policies.yaml` | [kubernetes-runtime.md](kubernetes-runtime.md) |
| 15 | Kubernetes Admission Control | `k8s/admission/` | [kubernetes-runtime.md](kubernetes-runtime.md) |
| 16 | eBPF Runtime Enforcement | `k8s/tetragon/` | [kubernetes-runtime.md](kubernetes-runtime.md) |

## Prompt Traversal Flow

The following diagram shows how a user prompt flows through all security
layers before reaching the LLM and how the LLM's output is filtered before
execution.

```
USER INPUT
    |
    v
+---------------------------+
| 1. Secret Redaction       |  Regex + entropy detection. Secrets replaced
|    secret-detector.ts     |  with [REDACTED_SECRET_N] placeholders.
+---------------------------+
    |  sanitized text
    v
+---------------------------+
| 2. Input Firewall Tier 1  |  20 regex patterns, <1ms. Zero-width char
|    input-firewall.ts      |  detection, homoglyph normalization,
|                           |  base64 decode-and-rescan.
+---------------------------+
    |  BLOCK if any pattern matches
    v
+---------------------------+
| 3. Input Firewall Tier 2  |  Heuristic scoring across 4 dimensions.
|    input-firewall.ts      |  >0.7 = BLOCK, 0.4-0.7 = FLAG
+---------------------------+
    |
    v
+---------------------------+
| 4. Injection Detection    |  30+ attack patterns across 12 categories.
|    prompt-injection-      |  MITRE ATLAS + CWE mappings.
|    detector.ts            |  Canary token system.
+---------------------------+  Multi-turn escalation analysis.
    |  BLOCK if riskScore >= 0.7
    v
+---------------------------+
| 5. Intent Classification  |  6 independent analyzers with weighted
|    intent-classifier.ts   |  signal fusion. Shannon entropy detection.
+---------------------------+  BLOCK if riskScore >= 0.7
    |
    v
+---------------------------+
| 6. Trajectory Check       |  Per-session risk score. If session is in
|    trajectory-monitor.ts  |  PAUSED state, all input is rejected.
+---------------------------+
    |
    v
+===========================+
|       LLM INFERENCE       |  Hardened system prompt with safety
|  (system-prompt.ts)       |  sandwiching + canary tokens.
+===========================+
    |  LLM output (tool calls)
    v
+---------------------------+
| 7. Output Command Filter  |  24 BLOCK patterns + 16 ALERT patterns.
|    output-filter.ts       |  Checks shell commands before execution.
+---------------------------+
    |
    v
+---------------------------+
| 8. Package Filter         |  Blocklist, typosquatting (Levenshtein),
|    package-filter.ts      |  age check, popularity check.
+---------------------------+
    |
    v
+---------------------------+
| COMMAND EXECUTION         |  Inside sandboxed K8s pod with:
| (workspace container)     |  - Cilium FQDN egress allowlist (L14)
|                           |  - Tetragon eBPF enforcement (L16)
|                           |  - Gatekeeper admission control (L15)
+---------------------------+
    |
    v
+---------------------------+
| 9-10. Session Scoring     |  Trajectory monitor adjusts risk per turn.
|   trajectory-monitor.ts   |  Behavioral detector runs LLM classification
|   behavioral-detector.ts  |  every 3 turns with 30s cooldown.
+---------------------------+
    |
    v
+---------------------------+
| 12. SIEM Rules Engine     |  13 detection rules + 3 correlation rules
|    siem-rules-engine.ts   |  process all security events in real time.
+---------------------------+
    |
    v
+---------------------------+
| 13. Incident Response     |  Automated actions: PAUSE_SESSION,
|    incident-response.ts   |  TERMINATE_WORKSPACE, NOTIFY, ESCALATE.
+---------------------------+
```

## Orchestration

The `SecurityLayer` class in `src/server/security/index.ts` chains layers
1-6 in `preprocessUserInput()` and layers 7-8 in `filterToolExecution()`.
Layers 9-10 run asynchronously via the event bus. Layers 11-16 operate
independently at the infrastructure level.

All security layers are wired into the runtime path:

- **Validation pipeline** is integrated into the agent loop's file-write
  path, enforcing policy checks on every file write operation.
- **Prometheus metrics** (`llm_tokens_total`, `tool_executions_total`,
  `agent_iterations_total`) are actively incremented from the agent loop
  during runtime.
- **Auth middleware** is applied to security API routes (`/api/security/*`),
  requiring authentication for all security endpoints.

## Source Files

All security source files live under `src/server/security/`. Kubernetes
policies live under `k8s/`. Wazuh rules live under `wazuh/`.

```
src/server/security/
  index.ts                    Orchestration (SecurityLayer class)
  input-firewall.ts           Layers 2-3
  prompt-injection-detector.ts Layer 4
  intent-classifier.ts        Layer 5
  system-prompt.ts            Layer 6
  output-filter.ts            Layer 7
  package-filter.ts           Layer 8
  trajectory-monitor.ts       Layer 9
  behavioral-detector.ts      Layer 10
  scanner.ts                  Layer 11 orchestrator
  sast-scanner.ts             Layer 11 (SAST)
  sca-scanner.ts              Layer 11 (SCA)
  secret-scanner.ts           Layer 11 (secrets)
  image-scanner.ts            Layer 11 (container images)
  secret-detector.ts          Layer 1
  siem-rules-engine.ts        Layer 12
  incident-response.ts        Layer 13
  runtime-correlator.ts       Layer 13

k8s/
  network-policies.yaml       Layer 14 (vanilla K8s)
  cilium/network-policies.yaml Layer 14 (Cilium)
  admission/                  Layer 15
  tetragon/                   Layer 16
  rbac.yaml                   RBAC
  workspace-pod-template.yaml Pod security context
```
