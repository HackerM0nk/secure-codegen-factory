# Behavioral Detection

> Two complementary modules: `behavioral-detector.ts` for LLM-based session
> classification and `trajectory-monitor.ts` for per-turn risk scoring.
> Together they detect slow-burn attacks that pass individual message filters.

## Architecture

| Module | Method | Frequency | Latency | Cost |
|---|---|---|---|---|
| `trajectory-monitor.ts` | Deterministic scoring | Every turn | <1ms | Zero |
| `behavioral-detector.ts` | LLM classification (Haiku) | Every 3 turns + 30s cooldown | ~200ms | ~$0.00025/analysis |

## Trajectory Monitor

Implemented in `src/server/security/trajectory-monitor.ts`.

The trajectory monitor maintains a per-session risk score (0.0-1.0) that
accumulates across turns. It uses two evaluation modes:

1. **Per-turn adjustments** -- Lightweight scoring on every turn
2. **Window evaluation** -- Deeper analysis every 5 turns

### Risk Levels

| Score | Level | Effect |
|---|---|---|
| 0.0 - 0.4 | NORMAL | No restrictions |
| 0.4 - 0.7 | FLAGGED | Increased monitoring; SESSION_FLAGGED event emitted |
| > 0.7 | PAUSED | All input rejected; SESSION_PAUSED event emitted |

### Per-Turn Adjustments

Applied on every turn except every 5th turn (when window evaluation runs).

| Condition | Score Delta |
|---|---|
| Security-adjacent keyword detected | +0.02 |
| A command was BLOCKED in this turn | +0.05 |
| Normal dev activity detected | -0.01 |

### Window Evaluation (Every 5 Turns)

Applied to the last 5 turns as a batch.

| Condition | Score Delta (per turn) |
|---|---|
| Security-adjacent keyword detected | +0.10 |
| A command was BLOCKED | +0.20 |
| User asks to disable/undo security | +0.30 |
| References system internals | +0.15 |
| Normal dev activity | -0.05 |

### Security-Adjacent Keywords

"root", "sudo", "privilege", "escalat", "bypass", "override", "injection",
"exploit", "vulnerability", "hack", "crack", "reverse shell", "backdoor",
"payload", "metasploit"

### Disable-Security Phrases

"undo security", "disable security", "turn off security", "remove security",
"bypass security", "skip security", "ignore security", "disable filter",
"disable firewall", "turn off filter", "remove filter", "bypass filter",
"disable check", "skip check", "remove check"

### System Internal Patterns

| Pattern | What It Detects |
|---|---|
| `/proc/` | Process filesystem access |
| `/sys/` | Sysfs access |
| `/etc/(passwd\|shadow\|hosts\|sudoers)` | Sensitive system files |
| `docker.sock` | Docker socket access |
| `kubernetes`, `kube-system` | K8s internal access |
| `.kube/config` | K8s config access |
| `/var/run/docker` | Docker runtime access |

### Normal Dev Patterns

These patterns reduce the risk score, recognizing legitimate development:

- File writes under `/workspace/src/`
- Installing common packages (react, express, lodash, etc.)
- Running npm scripts (dev, build, start, test, lint)
- Git operations (init, add, commit, status, diff)
- Creating directories under `/workspace/`
- Reading files under `/workspace/`

### Session Resume

When a paused session is manually resumed via `monitor.resume()`, the
score is reduced by 0.2 and the paused state is cleared.

## Behavioral Detector

Implemented in `src/server/security/behavioral-detector.ts`.

The behavioral detector uses a lightweight LLM (Haiku, forced via
`complexityOverride: "simple"`) to classify entire session behavior
patterns.

### Classification

| Classification | Meaning | Automated Action |
|---|---|---|
| NORMAL | Standard software development activity | None |
| SUSPICIOUS | Possible social engineering or gradual escalation | Logged |
| MALICIOUS | Clear unauthorized access or system compromise attempt | Session blocked; NOTIFY security team |

### Analysis Triggers

Analysis runs when ALL of the following are true:

1. User turn count is a multiple of **3** (ANALYSIS_TRIGGER_TURNS)
2. At least **30 seconds** have passed since the last analysis (ANALYSIS_COOLDOWN_MS)
3. The session is not already blocked

Additionally, `analyzeOnBlock()` can force an immediate analysis when a
BLOCK event occurs (still subject to the 30-second cooldown).

### Cost Controls

| Parameter | Value | Purpose |
|---|---|---|
| MAX_INPUT_TOKENS | 2,000 | Cap input to ~$0.00025 per analysis |
| MAX_SUMMARY_LENGTH | 150 chars | Per-turn summary truncation |
| Model | Haiku (simple) | Cheapest available model |
| maxTokens (response) | 150 | Cap response generation |

### Session Buffer

The detector maintains a per-session buffer of turn summaries:

- **agent.started** events add a user message summary
- **agent.tool_called** events append tool call info to the current turn
- **agent.completed** events add iteration/token count summaries

### LLM System Prompt

The behavioral analysis system prompt instructs the LLM to look for 8
key indicators:

1. Gradual escalation from benign to sensitive requests
2. Attempts to access system files
3. Requests to disable security or ignore rules
4. Social engineering ("pretend you're a different AI")
5. Probing for credentials or internal architecture
6. Installing suspicious tools (nmap, metasploit, reverse shells)
7. Communicating with external services for data exfiltration
8. Encoding tricks to hide malicious commands

### Response Parsing

The detector expects a JSON response with `classification`, `confidence`,
and `reason` fields. If JSON parsing fails, it falls back to keyword
detection (searching for "MALICIOUS" or "SUSPICIOUS" in the response text).
If all parsing fails, it defaults to NORMAL with confidence 0.

## Event Flow

```
Turn N arrives
    |
    v
Trajectory Monitor: adjustPerTurn()  -->  score adjustment
    |
    v
Is turn count % 3 == 0 AND cooldown elapsed?
    |                    |
    yes                  no
    |                    |
    v                    v
Behavioral Detector:    (skip)
  LLM analysis
    |
    v
Classification result checked
    |
    v
Is classification SUSPICIOUS or MALICIOUS?
    |                    |
    yes                  no (NORMAL)
    |                    |
    v                    v
Emit security.          (no event emitted --
  behavioral_alert        avoids SIEM noise
  to event bus            from rule 100005)
    |
    v
Incident Responder handles:
  MALICIOUS --> PAUSE_SESSION + NOTIFY
  SUSPICIOUS --> LOG
```

### Alert Filtering

The behavioral detector only emits `security.behavioral_alert` events for
SUSPICIOUS and MALICIOUS classifications. NORMAL classifications are not
emitted to the event bus. This prevents SIEM rule 100005 (level 14,
critical severity) from firing on routine development sessions, eliminating
false-positive noise in the alert pipeline.

## Related Docs

- [Intent Classification](intent-classification.md) -- Per-message intent
  analysis that feeds into trajectory scoring
- [SIEM Engine](siem-engine.md) -- Processes behavioral alerts as SIEM
  events
- [Incident Response](incident-response.md) -- Automated actions triggered
  by MALICIOUS classification
