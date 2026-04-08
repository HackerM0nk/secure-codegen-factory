# Product Security Model

> **Last updated**: 2026-04-08
>
> This document defines the security model for the AI Dev Factory v2 platform.
> Every claim is backed by a code reference. Where a control is incomplete or
> missing, the document says so. Read this as a contract between the security
> architecture and the engineering team -- not a marketing document.

---

## 1. Core Thesis

**The LLM is an untrusted, non-deterministic actor.**

Security does not rely on model safety training, RLHF alignment, or any
behavioral property of the model. The model is treated as a black box that may,
at any time, attempt to:

- Execute arbitrary shell commands
- Exfiltrate secrets from the environment
- Install malicious packages
- Write backdoored code
- Escalate privileges beyond the workspace sandbox
- Comply with injected instructions from user input or fetched content

The security architecture is therefore a set of **deterministic policy
enforcement layers outside the model**, each operating on observable artifacts
(text, commands, packages, code, network traffic, behavioral trajectories).
No single layer is trusted to catch everything. Defense-in-depth means that a
bypass of any one layer is contained by the others.

---

## 2. Product Lifecycle Primitives

Every user interaction flows through eight ordered stages. Each stage has a
defined trust boundary and a set of controls that apply at that boundary.

### Stage 1: Prompt Ingestion

The raw user message enters the system. This is the first and most critical
trust boundary -- user input is untrusted by definition.

**Controls applied**:
- Secret detection and redaction (`src/server/security/secret-detector.ts`)
- Input firewall regex + heuristic scoring (`src/server/security/input-firewall.ts`)
- Prompt injection detection (`src/server/security/prompt-injection-detector.ts`)
- Intent classification (`src/server/security/intent-classifier.ts`)
- Trajectory monitor pause check (`src/server/security/trajectory-monitor.ts`)

**Enforcement point**: `SecurityLayer.preprocessUserInput()` at
`src/server/security/index.ts:107-228`, called from `agent-loop.ts:115-117`.

### Stage 2: Context / Artifact Loading

The sanitized user message is combined with conversation history and the
hardened system prompt to form the LLM context window.

**Controls applied**:
- System prompt with safety sandwiching (`src/server/security/system-prompt.ts:6-25`)
- Only the sanitized (secret-redacted) input reaches the LLM (`agent-loop.ts:198`)
- Conversation history is passed through, but the original user input is always
  preprocessed before entering the message array (`agent-loop.ts:210-213`)

**Enforcement point**: `agent-loop.ts:210-213` (message construction) and
`agent-loop.ts:258` (system prompt passed to LLM router).

### Stage 3: Tool / Integration Invocation

The LLM produces tool calls (file_write, shell_exec, file_read, file_list).
Before any tool call executes, it passes through the output security filter.

**Controls applied**:
- Command denylist engine for shell_exec (`src/server/security/output-filter.ts`)
- Package install filter for npm/yarn/pnpm commands (`src/server/security/package-filter.ts`)
- Secret detection in file_write content (`src/server/security/index.ts:281-297`)
- Workspace path validation (`src/server/services/docker.ts:35-65`)

**Enforcement point**: `SecurityLayer.filterToolExecution()` at
`src/server/security/index.ts:232-300`, called from `agent-loop.ts:374`.

### Stage 4: Code Generation

The LLM writes files via the file_write tool. Generated code is validated for
structural correctness.

**Controls applied**:
- Post-write AST validation (`agent-loop.ts:419-429` calls `validationPipeline.runPostFileWrite()`)
- Secret detection in written content (Stage 3 control, `index.ts:281-297`)
- Path validation prevents writes outside /workspace (`docker.ts:35-65`)

**Enforcement point**: `agent-loop.ts:415-430` (file_write handler with AST check).

### Stage 5: Build / Run

Shell commands execute inside the sandboxed workspace container. The container
itself is the primary isolation boundary.

**Controls applied**:
- Container resource limits: 2GB memory, 2 CPUs, 256 PIDs (`docker.ts:27-31`)
- `no-new-privileges` security option (`docker.ts:195`)
- Command denylist blocks dangerous commands before they reach the container (`output-filter.ts`)
- Post-completion build verification (`agent-loop.ts:308-322` calls `validationPipeline.runPostCompletion()`)

**Enforcement point**: `docker.ts:160-197` (container creation with security constraints),
`agent-loop.ts:438-444` (shell_exec execution inside container).

### Stage 6: Preview

The workspace exposes a preview URL through Traefik reverse proxy. The preview
runs inside the same sandboxed container as the workspace.

**Controls applied**:
- Traefik routing with container-specific hostnames (`docker.ts:168-186`)
- Container network isolation (all containers on a shared Docker network --
  see Gap Assessment for limitations)
- Resource limits apply to the preview server (same container)

**Enforcement point**: `docker.ts:168-186` (Traefik labels), `docker.ts:188-196` (HostConfig).

### Stage 7: Publish / Deploy

A dedicated deployment pipeline runs pre-deploy security gates before building
and deploying the application.

**Controls applied**:
- SAST static analysis (`src/server/security/sast-scanner.ts` via `pre-deploy-gate.ts:63-81`)
- Secret scanning of all source files (`src/server/security/secret-scanner.ts` via `pre-deploy-gate.ts:84-101`)
- SCA dependency audit via npm audit (`src/server/security/sca-scanner.ts` via `pre-deploy-gate.ts:103-117`)
- SBOM generation in CycloneDX format (`src/server/security/sbom-generator.ts` via `pre-deploy-gate.ts:119-137`)
- Build test (`pre-deploy-gate.ts:139-150`)
- Gate verdict: deployment blocked if any critical finding exists (`pre-deploy-gate.ts:153`)

**Enforcement point**: `deployer.ts:33-46` calls `runPreDeployGate()` and aborts
deployment if the gate fails.

### Stage 8: Post-Publish Monitoring

Runtime monitoring of deployed containers and the overall system.

**Controls applied**:
- Trajectory monitoring across the session (`trajectory-monitor.ts`, recorded at `agent-loop.ts:507-512`)
- SIEM rules engine for event correlation (`src/server/security/siem-rules-engine.ts`, started at `index.ts:137-138`)
- Incident responder (`src/server/security/incident-response.ts`, started at `index.ts:130-131`)
- Runtime correlator (`src/server/security/runtime-correlator.ts`, started at `index.ts:133-134`)
- Prometheus metrics for all security events (`src/server/observability/metrics.ts`)
- Structured logging with correlation IDs (`src/server/observability/logger.ts`)

**Enforcement point**: `index.ts:129-138` (boot-time initialization of all monitoring subsystems).

---

## 3. Hard Invariants

These are the properties the system must maintain at all times. Each invariant
is annotated with its enforcement status based on code review.

### INV-1: No user input reaches the LLM without passing through the Input Security Chain

**Statement**: Every user message must pass through secret detection, input
firewall, prompt injection detector, and intent classifier before it is added
to the LLM context window.

**Enforced by**:
- `SecurityLayer.preprocessUserInput()` at `src/server/security/index.ts:107-228`
- Called unconditionally in `agent-loop.ts:115-117`
- If `preprocessResult.allowed` is false, the agent loop throws at `agent-loop.ts:163`
- The sanitized (secret-redacted) input is used for the LLM, never the raw input (`agent-loop.ts:198`)

**Status**: **ENFORCED**. The agent loop has no code path that bypasses
`preprocessUserInput()`. The four sub-checks (secret detection, firewall,
injection detector, intent classifier) all execute sequentially in
`preprocessUserInput()` at lines 112, 127, 143, and 172 of `index.ts`.

---

### INV-2: No LLM-generated command executes without Output Filter inspection

**Statement**: Every tool call produced by the LLM must pass through
`filterToolExecution()` before the tool's side effect occurs.

**Enforced by**:
- `SecurityLayer.filterToolExecution()` at `src/server/security/index.ts:232-300`
- Called for every tool block in the agent loop at `agent-loop.ts:374`
- If `filterResult.allowed` is false, the command is blocked at `agent-loop.ts:381-397`
- For `shell_exec`: command denylist + package filter (`index.ts:244-277`)
- For `file_write`: secret detection on content (`index.ts:281-297`)

**Status**: **ENFORCED**. The `for (const block of response.content)` loop at
`agent-loop.ts:346` processes every tool_use block, and `filterToolExecution()`
is called before any tool dispatch (`agent-loop.ts:374` precedes the switch
statement at `agent-loop.ts:414`).

---

### INV-3: No workspace can access files outside /workspace

**Statement**: All file read/write operations are restricted to paths under
`/workspace`. Path traversal attempts are rejected.

**Enforced by**:
- `validateWorkspacePath()` at `src/server/services/docker.ts:35-65`
- Rejects paths not starting with `/workspace` (`docker.ts:38-42`)
- Resolves and re-checks after normalization to prevent `..` traversal (`docker.ts:46-51`)
- Blocks sensitive patterns (`.git/config`, `.env.production`) (`docker.ts:54-64`)

**Status**: **ENFORCED** for file operations routed through the workspace service.
**ADVISORY** for shell_exec -- the output filter blocks some dangerous commands,
but a sufficiently creative shell command could read files outside `/workspace`
within the container. The container itself is the hard boundary; path validation
is a defense-in-depth layer within it.

---

### INV-4: No package installs without age, popularity, and typosquatting checks

**Statement**: Package installation commands (npm install, yarn add, pnpm add)
must pass through the package filter before execution.

**Enforced by**:
- `filterPackageInstall()` at `src/server/security/package-filter.ts`
- Detected by regex in `filterToolExecution()` at `src/server/security/index.ts:248-262`
- Checks: blocklist, age threshold, popularity threshold, typosquatting distance

**Status**: **ENFORCED** for commands that match the install regex pattern. The
regex at `index.ts:249-251` covers `npm install|i|add`, `yarn add`, and
`pnpm add|install`. A command that installs packages through an unconventional
method (e.g., `npx`, manual download, or a build script that runs `npm install`
internally) would bypass this check. The output filter's command denylist
provides a secondary catch for some of these cases.

---

### INV-5: All agent actions are attributable and auditable via the event bus

**Statement**: Every security-relevant action (input blocked, command blocked,
command alerted, secret detected, injection detected, intent classified,
trajectory flagged) must produce an event on the Redis Streams event bus with
a correlation ID.

**Enforced by**:
- Event emissions throughout `agent-loop.ts`:
  - Input blocked: `agent-loop.ts:130-135`
  - Injection detected: `agent-loop.ts:139-151` and `agent-loop.ts:181-195`
  - Intent blocked: `agent-loop.ts:152-161`
  - Intent flagged: `agent-loop.ts:167-178`
  - Secret detected: `agent-loop.ts:201-207`
  - Command blocked: `agent-loop.ts:387-393`
  - Command alerted: `agent-loop.ts:402-408`
  - Trajectory flagged: `agent-loop.ts:525-529`
  - Agent lifecycle: started (`agent-loop.ts:224-228`), iteration (`agent-loop.ts:240-244`),
    tool called (`agent-loop.ts:358-363`), tool result (`agent-loop.ts:474-480`),
    completed (`agent-loop.ts:300-305`), error (`agent-loop.ts:269-273`)
- Correlation IDs propagated from request context (`agent-loop.ts:112`)
- SIEM engine subscribes to all security events (`index.ts:137-138`)
- Audit logger subscribes to all events (`index.ts:39`, started at `index.ts:149`)

**Status**: **ENFORCED**. Every event emission in the agent loop includes
`correlationId`. The audit logger and SIEM engine are initialized at server boot.
Caveat: the `/api/security/test-input` endpoint calls `evaluateInput()` directly
(not through SecurityLayer), so those test calls do not produce event bus events.

---

### INV-6: No preview or deployed app is exposed without passing SAST, SCA, and secret scans

**Statement**: The pre-deploy gate must run SAST, SCA, and secret scanning
before any deployment proceeds. Critical findings block deployment.

**Enforced by**:
- `runPreDeployGate()` at `src/server/deploy/pre-deploy-gate.ts:56-157`
- Called from `deployer.ts:33`
- Gate blocks deployment if any check has a critical finding (`pre-deploy-gate.ts:153`)
- SAST: `scanFiles()` via `sast-scanner.ts` (`pre-deploy-gate.ts:64`)
- Secrets: `scanForSecrets()` via `secret-scanner.ts` (`pre-deploy-gate.ts:85`)
- SCA: `parseNpmAudit()` via `sca-scanner.ts` (`pre-deploy-gate.ts:106`)
- SBOM: `generateSbom()` via `sbom-generator.ts` (`pre-deploy-gate.ts:127`)

**Status**: **ENFORCED** for the deploy pipeline (`deployer.ts`). **NOT ENFORCED**
for preview URLs. The workspace preview (Traefik routing at port 3000) is live
as soon as the container starts -- there is no security gate between `npm run dev`
inside the workspace and the preview URL being accessible. The pre-deploy gate
only runs when `deployProject()` is called via `POST /api/deploy/:projectId`.

---

### INV-7: Every security miss must produce an observable event

**Statement**: When a security control blocks, alerts, or flags something, the
event must be observable via at least two channels: Redis Streams event bus and
Prometheus metrics.

**Enforced by**:
- Event bus emissions: see INV-5 above
- Prometheus metrics:
  - `tool_executions_total` with status label (`agent-loop.ts:460`)
  - `agent_iterations_total` with status label (`agent-loop.ts:247`, `agent-loop.ts:267`)
  - `llm_tokens_total` (`agent-loop.ts:284-285`)
  - HTTP request metrics via `httpMetricsMiddleware` (`index.ts:57`)
- SecurityLayer internal event handler (`index.ts:84-98`) fires on output filter events
- SecurityLayer `onSecurityEvent()` callback (`index.ts:101-103`)

**Status**: **ADVISORY**. Event bus emissions are comprehensive (see INV-5).
Prometheus metrics exist for tool execution and agent iteration counts, but there
are no dedicated Prometheus counters for security-specific events (e.g.,
`security_inputs_blocked_total`, `security_commands_blocked_total`,
`security_injections_detected_total`). Security events flow through Redis Streams
to the SIEM engine, but a Prometheus-native alerting path for security events
requires additional metric instrumentation.

---

### INV-8: The hardened system prompt cannot be overridden by user input

**Statement**: The system prompt is set by the platform, not the user. User input
cannot modify, replace, or append to the system prompt.

**Enforced by**:
- `HARDENED_SYSTEM_PROMPT` imported from `src/server/security/system-prompt.ts`
- Passed as the `system` parameter in the LLM call at `agent-loop.ts:258`
- The system prompt uses safety sandwiching with `[SYSTEM_BOUNDARY_START]` and
  `[SYSTEM_BOUNDARY_END]` markers (`system-prompt.ts:6-25`)
- User messages are added to the `messages` array, not the `system` parameter
  (`agent-loop.ts:210-213`)

**Status**: **ENFORCED**. There is no code path where user input modifies the
`system` parameter. The system prompt is a compile-time constant imported from
`system-prompt.ts`. Note: this does not prevent the LLM from *complying* with
injected instructions in user input -- that is an LLM behavioral property, not
a platform guarantee. The input firewall and injection detector (INV-1) are the
controls that address instruction injection at the input boundary.

---

### INV-9: Container resource consumption is bounded

**Statement**: Every workspace container has hard memory, CPU, and PID limits
that cannot be exceeded.

**Enforced by**:
- `RESOURCE_LIMITS` constant at `src/server/services/docker.ts:27-31`
- Applied in container creation at `docker.ts:190-192`
- Memory: 2GB, CPU: 2 cores, PIDs: 256
- `SecurityOpt: ["no-new-privileges"]` at `docker.ts:195`
- Deployed containers also have limits: 512MB memory, 1 CPU (`deployer.ts:97-98`)

**Status**: **ENFORCED**. Docker enforces these limits at the kernel level via
cgroups. The `no-new-privileges` flag prevents setuid/setgid escalation inside
the container. Note: `ReadonlyRootfs` is `false` (`docker.ts:194`) -- a
compromised process can write anywhere inside the container filesystem.

---

### INV-10: Session trajectories that exceed the risk threshold are automatically paused

**Statement**: If the cumulative risk score of a session crosses the pause
threshold, the agent loop halts and the session is blocked from further execution
until manually resumed.

**Enforced by**:
- `TrajectoryMonitor.addTurn()` at `src/server/security/trajectory-monitor.ts`
- Called from `agent-loop.ts:507-512` after each tool-use turn
- Pause check at `agent-loop.ts:515-537`: if `trajectoryResult.shouldPause`, the
  loop breaks and emits a `security_block` event
- Pre-LLM pause check in `preprocessUserInput()` at `index.ts:202-218`: if the
  monitor is in paused state, all further input is rejected
- Resume requires explicit call to `securityLayer.resumeSession()` (`index.ts:337-342`)

**Status**: **ENFORCED**. Both the mid-loop check (`agent-loop.ts:515`) and the
pre-input check (`index.ts:202`) enforce the pause. There is no API endpoint
that automatically resumes sessions -- manual intervention is required.

---

## 4. Invariant to Control Matrix

| Invariant | Input Firewall | Injection Detector | Intent Classifier | Secret Detector | Output Filter | Package Filter | Path Validation | Trajectory Monitor | SAST | SCA | Secret Scanner | System Prompt | Container Limits | Event Bus | SIEM |
|-----------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| INV-1: Input security chain | P | P | P | P | | | | C | | | | | | E | E |
| INV-2: Output filter | | | | | P | P | | | | | | | | E | E |
| INV-3: Path containment | | | | | S | | P | | | | | | B | | |
| INV-4: Package vetting | | | | | | P | | | | | | | | E | E |
| INV-5: Auditability | | | | | | | | | | | | | | P | P |
| INV-6: Pre-deploy gate | | | | | | | | | P | P | P | | | | |
| INV-7: Observable events | | | | | | | | | | | | | | P | P |
| INV-8: System prompt integrity | | | | | | | | | | | | P | | | |
| INV-9: Resource bounds | | | | | | | | | | | | | P | | |
| INV-10: Trajectory pause | | | | P | | | | P | | | | | | E | E |

**Legend**: P = Primary control, S = Secondary/supporting, B = Boundary (container is the hard limit), C = Contributes (pause state checked during preprocessing), E = Event emission/monitoring

---

## 5. Honest Gap Assessment

### What is genuinely enforced

These controls execute in the runtime path and have been verified through E2E testing:

1. **Input security chain (INV-1)**: All four sub-checks run on every user message.
   48-vector regression suite passes at 100%. E2E testing confirmed blocks for
   direct injection, crypto mining prompts, and social engineering attempts.

2. **Output filter (INV-2)**: Command denylist and package filter run on every
   `shell_exec` tool call. Known gap: `cat /proc/self/environ` bypasses the
   current pattern set (see `docs/known-gaps.md`).

3. **Path validation (INV-3)**: `validateWorkspacePath()` runs on all file
   operations through the workspace service.

4. **Pre-deploy gate (INV-6)**: SAST, SCA, secret scanning, and SBOM generation
   all execute before deployment. Critical findings block the deploy.

5. **System prompt (INV-8)**: Hardened prompt with safety sandwiching is applied
   to every LLM call. No user-controllable override path exists.

6. **Container limits (INV-9)**: Memory, CPU, PID limits, and `no-new-privileges`
   are enforced by Docker/cgroups at the kernel level.

7. **Trajectory monitoring (INV-10)**: Pause state is checked both pre-input and
   mid-loop. Sessions exceeding the risk threshold are halted.

### What is advisory (code exists, enforcement is partial)

1. **Package filter bypass (INV-4)**: The install-command regex covers standard
   package managers but does not catch `npx`, manual downloads, or packages
   installed via build scripts. The output filter provides some secondary coverage.

2. **Observable events (INV-7)**: Redis Streams events are comprehensive, but
   there are no dedicated Prometheus counters for security-specific events.
   Security alerting depends entirely on the SIEM engine processing Redis Stream
   events -- there is no direct Prometheus-to-AlertManager path for security blocks.

3. **Secret detection in file_write (INV-2 sub-control)**: Secrets in
   `file_write` content are detected and logged but the write is *allowed*
   (`index.ts:281-297`). This is intentional (`.env.example` patterns are
   legitimate) but means secrets can end up in generated code.

### What is missing

1. **Preview security gate**: Preview URLs are live as soon as `npm run dev`
   starts inside the container. There is no SAST/SCA/secret scan before preview
   exposure. The pre-deploy gate (INV-6) only runs for `POST /api/deploy`.
   An attacker could use the preview URL to serve malicious content without
   triggering any code scanning.

2. **Network isolation between workspaces**: All workspace containers share the
   same Docker network (`ai-dev-factory-v2_devfactory-v2`). Container A can
   reach container B via direct IP. There is no network policy enforcement in
   Docker mode. The K8s backend (`k8s-workspace.ts`) has NetworkPolicy
   definitions but is not the default runtime.

3. **Egress filtering**: Workspace containers have unrestricted outbound network
   access. A compromised workspace can exfiltrate data to arbitrary external
   hosts. The output filter blocks some reverse shell *commands*, but a
   determined attacker can craft HTTP-based exfiltration that bypasses command
   pattern matching.

4. **Rate limiting on security and deploy routes**: `/api/security` and
   `/api/deploy` routes have `authMiddleware()` but no `rateLimiter()` (compare
   `index.ts:82-83` vs `index.ts:77-79`). The security test endpoints accept
   arbitrary input and could be used for reconnaissance without rate limits.

5. **Deployed container security hardening**: The deployed container
   (`deployer.ts:84-99`) has memory and CPU limits but is missing
   `SecurityOpt: ["no-new-privileges"]`, `ReadonlyRootfs`, capability dropping,
   and PID limits that the workspace container has.

6. **Deploy route ownership verification**: `POST /api/deploy/:projectId`
   (`routes/deploy.ts:9-16`) calls `deployProject()` with `req.user!.id` but
   does not verify that the user owns the project before deploying. Any
   authenticated user could trigger a deployment for any project ID.

7. **Prometheus security metrics**: No dedicated counters for
   `security_inputs_blocked_total`, `security_commands_blocked_total`,
   `security_injections_detected_total`, `security_secrets_detected_total`.
   Security observability depends on Redis Streams + SIEM, with no native
   Prometheus alerting path.

8. **Read-only root filesystem**: `ReadonlyRootfs: false` on workspace
   containers (`docker.ts:194`). A compromised process can modify system
   binaries, install persistence mechanisms, or tamper with security tooling
   inside the container.

### Invariant status summary

| # | Invariant | Status |
|---|-----------|--------|
| INV-1 | Input security chain | **ENFORCED** |
| INV-2 | Output filter inspection | **ENFORCED** (file_write secret check is advisory) |
| INV-3 | Path containment | **ENFORCED** for file ops; shell_exec relies on container boundary |
| INV-4 | Package vetting | **ENFORCED** for standard install commands; bypass via npx/scripts possible |
| INV-5 | Auditability | **ENFORCED** |
| INV-6 | Pre-deploy gate | **ENFORCED** for deploy; **MISSING** for preview |
| INV-7 | Observable events | **ADVISORY** -- Redis Streams yes, Prometheus security counters no |
| INV-8 | System prompt integrity | **ENFORCED** |
| INV-9 | Resource bounds | **ENFORCED** (ReadonlyRootfs gap noted) |
| INV-10 | Trajectory pause | **ENFORCED** |

---

## Appendix: File Reference Index

| File | Role |
|------|------|
| `src/server/security/index.ts` | SecurityLayer class -- chains all security components |
| `src/server/security/input-firewall.ts` | Tier 1 regex + Tier 2 heuristic input scoring |
| `src/server/security/prompt-injection-detector.ts` | Multi-vector prompt injection detection |
| `src/server/security/intent-classifier.ts` | Semantic intent classification with weighted signal fusion |
| `src/server/security/secret-detector.ts` | Real-time secret detection and redaction in user input |
| `src/server/security/output-filter.ts` | Post-LLM command denylist engine |
| `src/server/security/package-filter.ts` | Package install vetting (age, popularity, typosquatting) |
| `src/server/security/trajectory-monitor.ts` | Per-session cumulative risk scoring |
| `src/server/security/system-prompt.ts` | Hardened system prompt with safety sandwiching |
| `src/server/security/sast-scanner.ts` | Static analysis with semgrep-like pattern matching |
| `src/server/security/sca-scanner.ts` | npm audit parser for dependency vulnerabilities |
| `src/server/security/secret-scanner.ts` | Bulk file secret scanning (TruffleHog-style) |
| `src/server/security/sbom-generator.ts` | CycloneDX SBOM generation |
| `src/server/security/siem-rules-engine.ts` | Real-time event correlation and detection rules |
| `src/server/security/incident-response.ts` | Automated incident response actions |
| `src/server/security/runtime-correlator.ts` | Cross-event runtime correlation |
| `src/server/security/behavioral-detector.ts` | LLM-based session behavioral classification (opt-in) |
| `src/server/services/agent-loop.ts` | Agent loop with security integration at every stage |
| `src/server/services/docker.ts` | Docker workspace management with security constraints |
| `src/server/deploy/pre-deploy-gate.ts` | Pre-deployment security gate (SAST + SCA + secrets + SBOM) |
| `src/server/deploy/deployer.ts` | Deployment pipeline with gate enforcement |
| `src/server/index.ts` | Server bootstrap -- wires all security subsystems |
