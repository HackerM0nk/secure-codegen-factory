// src/server/security/input-firewall.ts
// Two-tier pre-LLM input firewall: Regex (<1ms) + Heuristic scoring (<5ms)

export interface FirewallResult {
  blocked: boolean;
  score: number;
  reason: string;
  tier: string;
  matchedPatterns: string[];
}

// ── Tier 1: Regex-based instant detection ──────────────────────────────────

const TIER1_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  // Direct injection attempts
  { name: "ignore_previous", regex: /ignore\s+(all\s+)?previous\s+(instructions|prompts|context)/i },
  { name: "disregard_above", regex: /disregard\s+(everything\s+)?(above|prior|previous)/i },
  { name: "forget_instructions", regex: /forget\s+(your|all|prior|previous|everything)\s+(instructions|rules|guidelines|constraints|above|before)/i },

  // System prompt extraction
  { name: "system_prompt_ref", regex: /\b(system\s*prompt|systemprompt)\b/i },
  { name: "system_role_marker", regex: /\bSYSTEM\s*:/i },
  { name: "system_bracket", regex: /\[SYSTEM\]/i },
  { name: "llama_sys_tag", regex: /<<SYS>>|<\/s>/i },

  // DAN / jailbreak
  { name: "dan_mode", regex: /\b(DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled)\b/i },
  { name: "jailbreak_keyword", regex: /\b(jailbreak|jail\s*break|uncensored\s+mode|unrestricted\s+mode)\b/i },

  // XML/markdown delimiter injection
  { name: "xml_instruction_close", regex: /<\/instruction>|<\/system>|<\/rules>/i },
  { name: "llama_inst_close", regex: /\[\/INST\]/i },
  { name: "markdown_role_injection", regex: /(###|---)\s*(system|assistant|instructions?)\s*[:]/i },

  // Reverse shell / exploit patterns in user text
  { name: "reverse_shell_in_prompt", regex: /bash\s+-i\s+>&\s*\/dev\/tcp\//i },
  { name: "nc_reverse_shell_in_prompt", regex: /\bnc\b.*-e\s*\/bin\/(ba)?sh/i },

  // Indirect injection via HTML comments or hidden markers
  { name: "html_comment_injection", regex: /<!--\s*(?:IMPORTANT|SYSTEM|OVERRIDE|INSTRUCTION|NOTE\s*TO\s*AI)[\s\S]{0,200}?-->/i },
  { name: "hidden_instruction_marker", regex: /\[(?:SYSTEM\s*OVERRIDE|IMPORTANT|NEW\s*DIRECTIVE|ADMIN\s*INSTRUCTION)\]/i },

  // "Repeat above" extraction variant
  { name: "repeat_above_extraction", regex: /\brepeat\s+(everything|all|every\s+single\s+character|the\s+text)\s+(above|before)\b/i },
];

// Unicode zero-width and homoglyph detection
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/;
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic uppercase → Latin
  "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041D": "H",
  "\u041A": "K", "\u041C": "M", "\u041E": "O", "\u0420": "P", "\u0422": "T",
  "\u0425": "X", "\u0406": "I", "\u0407": "I",
  // Cyrillic lowercase → Latin
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
  "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0455": "s", "\u0456": "i",
  "\u0458": "j", "\u04BB": "h", "\u0501": "d", "\u04CF": "l",
};

function normalizeHomoglyphs(text: string): string {
  let result = text;
  for (const [glyph, ascii] of Object.entries(HOMOGLYPH_MAP)) {
    result = result.replaceAll(glyph, ascii);
  }
  return result;
}

function containsZeroWidth(text: string): boolean {
  return ZERO_WIDTH_REGEX.test(text);
}

function detectBase64Blocks(text: string): string[] {
  const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
  const matches = text.match(base64Regex) || [];
  const decoded: string[] = [];
  for (const match of matches) {
    try {
      const buf = Buffer.from(match, "base64");
      const str = buf.toString("utf-8");
      // Only consider it valid base64 if the decoded string is mostly printable ASCII
      const printableRatio = str.split("").filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length / str.length;
      if (printableRatio > 0.8 && str.length > 5) {
        decoded.push(str);
      }
    } catch {
      // not valid base64, skip
    }
  }
  return decoded;
}

function runTier1(text: string): { blocked: boolean; matchedPatterns: string[] } {
  const normalized = normalizeHomoglyphs(text);
  const matched: string[] = [];

  // Check raw and normalized text against all patterns
  for (const { name, regex } of TIER1_PATTERNS) {
    if (regex.test(text) || regex.test(normalized)) {
      matched.push(name);
    }
  }

  // Zero-width character check
  if (containsZeroWidth(text)) {
    matched.push("zero_width_chars");
  }

  // Base64 block detection: decode and re-scan
  const decodedBlocks = detectBase64Blocks(text);
  for (const decoded of decodedBlocks) {
    for (const { name, regex } of TIER1_PATTERNS) {
      if (regex.test(decoded)) {
        matched.push(`base64_encoded:${name}`);
      }
    }
  }

  return { blocked: matched.length > 0, matchedPatterns: matched };
}

// ── Tier 2: Heuristic scoring (<5ms) ───────────────────────────────────────

const IMPERATIVE_SYSTEM_VERBS = [
  "ignore", "forget", "disregard", "override", "bypass", "skip", "disable",
  "pretend", "act as", "roleplay", "simulate", "behave as", "you are now",
  "new instructions", "updated instructions", "revised instructions",
  "from now on", "henceforth", "going forward you must",
];

const ROLE_PLAY_MARKERS = [
  "you are now", "act as if", "pretend to be", "simulate being",
  "enter .* mode", "switch to .* mode", "enable .* mode",
  "you have been reprogrammed", "your new identity",
];

const ENCODING_PATTERNS = [
  { name: "base64_command", regex: /\b(base64|b64decode|atob)\b/i },
  { name: "hex_encoding", regex: /\\x[0-9a-fA-F]{2}/g },
  { name: "rot13_ref", regex: /\brot13\b/i },
  { name: "unicode_escape", regex: /\\u[0-9a-fA-F]{4}/g },
];

function computeHeuristicScore(text: string): { score: number; breakdown: Record<string, number> } {
  const lower = text.toLowerCase();
  const breakdown: Record<string, number> = {};

  // 1. Instruction-like tokens
  let verbCount = 0;
  for (const verb of IMPERATIVE_SYSTEM_VERBS) {
    if (lower.includes(verb)) verbCount++;
  }
  const verbScore = Math.min(verbCount * 0.12, 0.4);
  breakdown["imperative_verbs"] = verbScore;

  // 2. Role-play / persona markers
  let rolePlayCount = 0;
  for (const marker of ROLE_PLAY_MARKERS) {
    const markerRegex = new RegExp(marker, "i");
    if (markerRegex.test(lower)) rolePlayCount++;
  }
  const rolePlayScore = Math.min(rolePlayCount * 0.2, 0.4);
  breakdown["role_play_markers"] = rolePlayScore;

  // 3. Ratio of meta-instructions to content
  const words = text.split(/\s+/).filter(Boolean);
  const totalWords = words.length;
  if (totalWords > 0) {
    const metaWords = IMPERATIVE_SYSTEM_VERBS.filter((v) => lower.includes(v)).length;
    const metaRatio = metaWords / totalWords;
    const metaScore = Math.min(metaRatio * 3, 0.3);
    breakdown["meta_ratio"] = metaScore;
  } else {
    breakdown["meta_ratio"] = 0;
  }

  // 4. Encoding attempts
  let encodingScore = 0;
  for (const { name, regex } of ENCODING_PATTERNS) {
    const matches = text.match(regex);
    if (matches) {
      encodingScore += 0.1;
    }
  }
  encodingScore = Math.min(encodingScore, 0.3);
  breakdown["encoding_attempts"] = encodingScore;

  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);
  return { score: Math.min(total, 1.0), breakdown };
}

// ── Public API ──────────────────────────────────────────────────────────────

export function evaluateInput(text: string): FirewallResult {
  // Tier 1: Regex-based (<1ms)
  const tier1 = runTier1(text);
  if (tier1.blocked) {
    return {
      blocked: true,
      score: 1.0,
      reason: `Tier 1 regex match: ${tier1.matchedPatterns.join(", ")}`,
      tier: "tier1",
      matchedPatterns: tier1.matchedPatterns,
    };
  }

  // Tier 2: Heuristic scoring (<5ms)
  const tier2 = computeHeuristicScore(text);

  if (tier2.score > 0.7) {
    return {
      blocked: true,
      score: tier2.score,
      reason: `Tier 2 heuristic score ${tier2.score.toFixed(2)} exceeds threshold. Breakdown: ${JSON.stringify(tier2.breakdown)}`,
      tier: "tier2",
      matchedPatterns: Object.keys(tier2.breakdown).filter((k) => tier2.breakdown[k] > 0),
    };
  }

  const flagged = tier2.score >= 0.4;
  return {
    blocked: false,
    score: tier2.score,
    reason: flagged
      ? `Tier 2 flagged (score ${tier2.score.toFixed(2)}): review recommended`
      : "Input passed security checks",
    tier: "tier2",
    matchedPatterns: Object.keys(tier2.breakdown).filter((k) => tier2.breakdown[k] > 0),
  };
}
