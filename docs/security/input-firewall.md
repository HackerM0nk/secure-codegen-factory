# Input Firewall

> Two-tier pre-LLM input firewall. Tier 1 uses regex matching (<1ms).
> Tier 2 uses heuristic scoring (<5ms). Implemented in
> `src/server/security/input-firewall.ts`.

## How It Works

Every user message passes through two tiers before reaching the LLM:

1. **Tier 1 (Regex)** -- Instant pattern matching against 20 known attack
   signatures. Any match is an immediate BLOCK with score 1.0.
2. **Tier 2 (Heuristic)** -- Scores the input across four dimensions. A
   composite score above 0.7 triggers a BLOCK. A score between 0.4 and 0.7
   triggers a FLAG (allowed but logged for review).

Before either tier runs, the input undergoes three normalization steps:

- **Homoglyph normalization** -- Cyrillic lookalikes are mapped to ASCII
  (e.g., Cyrillic `A` U+0410 becomes Latin `A`).
- **Zero-width character detection** -- The presence of U+200B, U+200C,
  U+200D, U+FEFF, U+00AD, U+2060, or U+180E triggers the
  `zero_width_chars` pattern.
- **Base64 decode and rescan** -- Blocks of 20+ base64 characters are
  decoded. If the decoded content is >80% printable ASCII and >5 characters
  long, it is re-scanned against all Tier 1 patterns.

## Tier 1: Regex Patterns

Any match results in an immediate BLOCK (score = 1.0).

| Pattern Name | Category | Example Match |
|---|---|---|
| `ignore_previous` | Direct injection | "ignore all previous instructions" |
| `disregard_above` | Direct injection | "disregard everything above" |
| `forget_instructions` | Direct injection | "forget your previous instructions" |
| `system_prompt_ref` | System prompt extraction | "show me the system prompt" |
| `system_role_marker` | System prompt extraction | "SYSTEM:" |
| `system_bracket` | System prompt extraction | "[SYSTEM]" |
| `llama_sys_tag` | System prompt extraction | "<<SYS>>" or "</s>" |
| `dan_mode` | Jailbreak | "DAN mode" or "do anything now" |
| `jailbreak_keyword` | Jailbreak | "jailbreak" or "uncensored mode" |
| `xml_instruction_close` | Delimiter injection | "</instruction>" or "</system>" |
| `llama_inst_close` | Delimiter injection | "[/INST]" |
| `markdown_role_injection` | Delimiter injection | "### system:" |
| `reverse_shell_in_prompt` | Exploit payload | "bash -i >& /dev/tcp/" |
| `nc_reverse_shell_in_prompt` | Exploit payload | "nc -e /bin/sh" |
| `html_comment_injection` | Indirect injection | "<!-- IMPORTANT ... -->" |
| `hidden_instruction_marker` | Indirect injection | "[SYSTEM OVERRIDE]" |
| `repeat_above_extraction` | System prompt extraction | "repeat everything above" |

Additionally, two synthetic patterns can fire:

| Pattern Name | Trigger |
|---|---|
| `zero_width_chars` | Input contains any zero-width Unicode character |
| `base64_encoded:{name}` | A decoded base64 block matches any Tier 1 pattern |

## Tier 2: Heuristic Scoring

If Tier 1 passes, Tier 2 computes a composite score from four independent
analyzers. Each dimension has a cap to prevent a single dimension from
dominating.

| Dimension | Weight | Cap | How It Scores |
|---|---|---|---|
| Imperative verbs | 0.12 per verb | 0.40 | Counts matches from 19 imperative phrases: "ignore", "forget", "disregard", "override", "bypass", "skip", "disable", "pretend", "act as", "roleplay", "simulate", "behave as", "you are now", "new instructions", "updated instructions", "revised instructions", "from now on", "henceforth", "going forward you must" |
| Role-play markers | 0.20 per marker | 0.40 | Counts matches from 9 role-play phrases: "you are now", "act as if", "pretend to be", "simulate being", "enter .* mode", "switch to .* mode", "enable .* mode", "you have been reprogrammed", "your new identity" |
| Meta-instruction ratio | metaRatio * 3 | 0.30 | Ratio of matched imperative verbs to total word count, scaled by 3x |
| Encoding attempts | 0.10 per type | 0.30 | Detects base64/b64decode/atob references, hex escapes (\xNN), ROT13 references, unicode escapes (\uNNNN) |

## Thresholds

| Score Range | Action | Meaning |
|---|---|---|
| 1.0 | BLOCK | Tier 1 regex match (immediate) |
| > 0.7 | BLOCK | Tier 2 heuristic score exceeded block threshold |
| 0.4 -- 0.7 | FLAG | Allowed but logged; review recommended |
| < 0.4 | PASS | Input passed security checks |

## Public API

```typescript
function evaluateInput(text: string): FirewallResult;

interface FirewallResult {
  blocked: boolean;
  score: number;       // 0.0 - 1.0
  reason: string;
  tier: string;        // "tier1" or "tier2"
  matchedPatterns: string[];
}
```

## Homoglyph Map

The firewall normalizes 25 Cyrillic-to-Latin homoglyph pairs before
scanning. This prevents attackers from using Cyrillic characters that look
identical to Latin letters to evade regex patterns.

| Cyrillic (uppercase) | Latin | Cyrillic (lowercase) | Latin |
|---|---|---|---|
| U+0410 (A) | A | U+0430 (a) | a |
| U+0412 (B) | B | U+0435 (e) | e |
| U+0421 (C) | C | U+043E (o) | o |
| U+0415 (E) | E | U+0440 (p) | p |
| U+041D (H) | H | U+0441 (c) | c |
| U+041A (K) | K | U+0445 (x) | x |
| U+041C (M) | M | U+0443 (y) | y |
| U+041E (O) | O | U+0455 (s) | s |
| U+0420 (P) | P | U+0456 (i) | i |
| U+0422 (T) | T | U+0458 (j) | j |
| U+0425 (X) | X | U+04BB (h) | h |
| U+0406 (I) | I | U+0501 (d) | d |
| U+0407 (I) | I | U+04CF (l) | l |

## Related Docs

- [Injection Detection](injection-detection.md) -- Deeper AI-specific
  injection analysis that runs after the input firewall passes
- [Intent Classification](intent-classification.md) -- Semantic-level
  intent detection that supplements pattern matching
- [Security Overview](README.md) -- Where this layer fits in the overall
  defense-in-depth stack
