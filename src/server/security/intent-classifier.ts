// src/server/security/intent-classifier.ts
// Prompt intent classification — goes beyond regex to detect semantic attack intent
// Uses weighted signal fusion from multiple heuristic analyzers

import { createLogger } from "../observability/logger";

const logger = createLogger("intent-classifier");

// ── Intent Categories ─────────────────────────────────────────────────────

export type IntentCategory =
  | "BENIGN_DEV"        // Normal development request
  | "RECONNAISSANCE"    // Probing system boundaries, testing what's allowed
  | "PRIVILEGE_ESCALATION" // Trying to gain more access
  | "EXFILTRATION"      // Trying to extract data or secrets
  | "RESOURCE_ABUSE"    // Crypto mining, spam, etc.
  | "SOCIAL_ENGINEERING" // Manipulating the AI's behavior
  | "EVASION"           // Trying to bypass security controls
  | "SABOTAGE";         // Destructive intent

export interface IntentSignal {
  source: string;       // Which analyzer produced this signal
  category: IntentCategory;
  confidence: number;   // 0.0 - 1.0
  evidence: string;
  weight: number;       // How much this signal contributes to final score
}

export interface IntentClassification {
  primaryIntent: IntentCategory;
  confidence: number;
  signals: IntentSignal[];
  riskScore: number;    // 0.0 - 1.0 composite
  recommendation: "ALLOW" | "FLAG" | "BLOCK";
  explanation: string;
}

// ── Signal Analyzers ──────────────────────────────────────────────────────

/**
 * Analyzes imperative structure — commands directed at the AI itself
 * vs. commands about the code/project.
 */
function analyzeImperativeTarget(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];
  const lower = input.toLowerCase();

  // Commands directed at the AI's behavior
  const selfDirectedPatterns = [
    { re: /\b(you must|you should|you will|you need to)\s+(now|always|never|stop|start|forget|ignore|disable|enable|override|bypass|skip)/i, cat: "SOCIAL_ENGINEERING" as IntentCategory, ev: "Imperative directed at AI behavior" },
    { re: /\b(from now on|starting now|for the rest of|henceforth|going forward)\b/i, cat: "SOCIAL_ENGINEERING" as IntentCategory, ev: "Temporal scope override attempt" },
    { re: /\b(pretend|imagine|suppose|assume|act as if|let's say)\s+(you|there|we|the|that)/i, cat: "SOCIAL_ENGINEERING" as IntentCategory, ev: "Hypothetical framing to bypass rules" },
    { re: /\b(don't|do not|never)\s+(tell|mention|say|report|log|flag|alert|block)/i, cat: "EVASION" as IntentCategory, ev: "Requesting suppression of safety reporting" },
    { re: /\b(for privacy|for security)\s+(reasons?|purposes?)\b.{0,40}\b(don't|do not|skip|no)\s+(log|report|track|record|flag)/i, cat: "EVASION" as IntentCategory, ev: "Framing logging suppression as privacy concern" },
    { re: /\b(emergency|urgent|critical|immediately|right now|time is critical)\b.{0,50}\b(run|execute|do|perform|skip|bypass)\b/i, cat: "SOCIAL_ENGINEERING" as IntentCategory, ev: "Urgency-based manipulation to bypass safety" },
    { re: /\b(skip|bypass|ignore)\s+(all\s+)?(checks?|validation|security|verification|safety)/i, cat: "SOCIAL_ENGINEERING" as IntentCategory, ev: "Explicit request to skip safety checks" },
  ];

  for (const { re, cat, ev } of selfDirectedPatterns) {
    if (re.test(input)) {
      signals.push({ source: "imperative-target", category: cat, confidence: 0.6, evidence: ev, weight: 1.2 });
    }
  }

  // Code-directed commands (benign) — subtract from suspicion
  const codeDirected = [
    /\b(create|build|write|implement|add|make|generate|refactor|fix|update|test)\s+(a |the |an |my )?(component|function|file|class|module|api|endpoint|page|hook|test|style)/i,
    /\b(install|import|configure|setup|deploy|run|start|stop|lint|format)\b/i,
  ];

  let codeScore = 0;
  for (const re of codeDirected) {
    if (re.test(input)) codeScore += 0.3;
  }

  if (codeScore > 0) {
    signals.push({
      source: "imperative-target",
      category: "BENIGN_DEV",
      confidence: Math.min(codeScore, 0.9),
      evidence: "Contains standard development commands",
      weight: 1.5, // Higher weight — benign dev is strong signal
    });
  }

  return signals;
}

/**
 * Detects information-gathering intent — questions about system internals,
 * architecture, credentials, or security measures.
 */
function analyzeReconIntent(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];

  const reconPatterns = [
    { re: /\b(what|where|how|show|list|display|reveal|tell me)\b.{0,30}\b(system prompt|instructions|rules|constraints|guidelines|configuration|credentials|secrets|environment variables|env vars|\.env)\b/i, conf: 0.8, ev: "Querying system internals" },
    { re: /\b(what|which)\s+(security|safety|filter|firewall|block|limitation|restriction|check)\b/i, conf: 0.5, ev: "Probing security boundaries" },
    { re: /\b(can you|are you able to|is it possible to|what happens if|try to)\b.{0,30}\b(access|read|write|delete|execute|connect|curl|wget|ssh)\b.{0,30}\b(outside|external|remote|internet|other|host|root|admin|etc)\b/i, conf: 0.7, ev: "Testing sandbox boundaries" },
    { re: /\b(what|who|where)\s+(am i|is my|are the)\b.{0,20}\b(user|role|permission|org|account|access|privilege)\b/i, conf: 0.4, ev: "Querying identity/permissions" },
    { re: /\b(what|which)\s+(model|version|provider|api|llm|backend|infrastructure)\s+(are you|do you|is)\b/i, conf: 0.3, ev: "Querying platform architecture" },
  ];

  for (const { re, conf, ev } of reconPatterns) {
    if (re.test(input)) {
      signals.push({ source: "recon-intent", category: "RECONNAISSANCE", confidence: conf, evidence: ev, weight: 1.0 });
    }
  }

  return signals;
}

/**
 * Detects privilege escalation intent — trying to gain access beyond
 * what's allowed.
 */
function analyzePrivEscIntent(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];

  const privEscPatterns = [
    { re: /\b(run as|switch to|become|elevate|sudo|su\s|admin|root|superuser|operator)\b/i, conf: 0.7, ev: "Privilege escalation language" },
    { re: /\b(override|bypass|disable|turn off|remove|skip|ignore)\s+(the |all )?(security|safety|filter|firewall|sandbox|restriction|limit|checks?|validation|authentication|authorization)\b/i, conf: 0.9, ev: "Explicit security bypass request" },
    { re: /\b(i am|i'm)\s+(an? |the )?(system\s+)?(admin|administrator|developer|owner|authorized|root|superuser|operator|security\s+team)\b/i, conf: 0.8, ev: "False authority claim" },
    { re: /\b(emergency|urgent|critical|override)\s+(mode|access|protocol|instruction|code)\b/i, conf: 0.7, ev: "Urgency-based escalation" },
    { re: /\b(i have|i've got)\s+(full\s+)?(root|admin|sudo|superuser)\s+(access|privilege|permission)\b/i, conf: 0.85, ev: "Claiming elevated privileges" },
    { re: /\b(maintenance|debug|test|developer|admin)\s+(mode|access|console|panel)\b/i, conf: 0.6, ev: "Requesting privileged mode" },
  ];

  for (const { re, conf, ev } of privEscPatterns) {
    if (re.test(input)) {
      signals.push({ source: "privesc-intent", category: "PRIVILEGE_ESCALATION", confidence: conf, evidence: ev, weight: 1.3 });
    }
  }

  return signals;
}

/**
 * Detects exfiltration intent — trying to send data outside
 * the workspace/system.
 */
function analyzeExfilIntent(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];

  const exfilPatterns = [
    { re: /\b(send|post|upload|transmit|forward|exfiltrate|transfer)\b.{0,40}\b(to|via|using|through)\b.{0,40}\b(url|webhook|endpoint|server|api|http|ftp|external)\b/i, conf: 0.7, ev: "Data transmission to external target" },
    { re: /\b(curl|wget|fetch|http|request)\b.{0,30}\b(post|put|send)\b/i, conf: 0.5, ev: "HTTP outbound request with data" },
    { re: /\b(encode|compress|zip|tar|base64)\b.{0,30}\b(send|upload|post|transmit)\b/i, conf: 0.6, ev: "Encoding before transmission" },
    { re: /\b(read|cat|dump|export)\b.{0,30}\b(\.env|secret|credential|key|token|password|config)\b.{0,30}\b(send|post|curl|output)\b/i, conf: 0.9, ev: "Reading credentials then transmitting" },
    { re: /\b(dns|icmp|nslookup|dig)\b.{0,20}\b(tunnel|exfil|encode|query)\b/i, conf: 0.8, ev: "DNS/ICMP tunneling" },
  ];

  for (const { re, conf, ev } of exfilPatterns) {
    if (re.test(input)) {
      signals.push({ source: "exfil-intent", category: "EXFILTRATION", confidence: conf, evidence: ev, weight: 1.4 });
    }
  }

  return signals;
}

/**
 * Detects evasion techniques — encoding, obfuscation, time-delayed attacks.
 */
function analyzeEvasionIntent(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];

  // High entropy sections (potential encoded payloads)
  const words = input.split(/\s+/);
  const longTokens = words.filter((w) => w.length > 30 && !/^https?:\/\//.test(w));
  if (longTokens.length > 0) {
    const avgEntropy = longTokens.reduce((sum, w) => sum + shannonEntropy(w), 0) / longTokens.length;
    if (avgEntropy > 4.0) {
      signals.push({
        source: "evasion-intent",
        category: "EVASION",
        confidence: Math.min(avgEntropy / 6.0, 0.8),
        evidence: `High-entropy tokens detected (avg entropy=${avgEntropy.toFixed(2)})`,
        weight: 0.8,
      });
    }
  }

  // Multi-step instructions that separate the attack
  const stepPatterns = /\b(step\s+\d|first|then|next|after that|finally|once done)\b/gi;
  const stepMatches = input.match(stepPatterns) || [];
  if (stepMatches.length >= 3) {
    // Check if any step involves security-sensitive action
    const sensitiveSteps = /\b(step\s+\d|then|after|finally)\b.{0,80}\b(curl|wget|exec|eval|rm|chmod|sudo|nc|ncat|base64|env|secret|password)\b/gi;
    if (sensitiveSteps.test(input)) {
      signals.push({
        source: "evasion-intent",
        category: "EVASION",
        confidence: 0.6,
        evidence: "Multi-step instructions with sensitive commands — possible staged attack",
        weight: 1.0,
      });
    }
  }

  // Time-delayed or conditional execution
  const delayPatterns = /\b(sleep|wait|timeout|after\s+\d+\s+(second|minute)|at\s+\d+:\d+|cron|schedule)\b/i;
  if (delayPatterns.test(input) && /\b(curl|wget|rm|eval|exec|nc)\b/i.test(input)) {
    signals.push({
      source: "evasion-intent",
      category: "EVASION",
      confidence: 0.6,
      evidence: "Time-delayed sensitive command execution",
      weight: 1.0,
    });
  }

  return signals;
}

/**
 * Detects resource abuse intent — crypto mining, spam, DDoS.
 */
function analyzeResourceAbuseIntent(input: string): IntentSignal[] {
  const signals: IntentSignal[] = [];

  const abusePatterns = [
    { re: /\b(mine|miner|mining|xmrig|cpuminer|hashrate|monero|crypto)\b/i, conf: 0.9, ev: "Crypto mining terminology" },
    { re: /\b(ddos|flood|stress\s*test|load\s*test|hammer)\b.{0,30}\b(server|endpoint|api|site|url|their)\b/i, conf: 0.7, ev: "DDoS/flooding intent" },
    { re: /\b\d{3,}\s*(http\s+)?requests?\s+(per|every|a)\s+(second|minute)\b/i, conf: 0.8, ev: "High-volume request flooding" },
    { re: /\bsends?\s+\d{3,}\s.*requests?\b/i, conf: 0.8, ev: "Mass request volume abuse" },
    { re: /\b(spam|bulk|mass)\s+(send|email|message|request|post)\b/i, conf: 0.7, ev: "Spam/bulk messaging intent" },
    { re: /\bwhile\s+(true|1)\b.{0,30}\b(curl|wget|request|fetch)\b/i, conf: 0.8, ev: "Infinite loop with outbound requests" },
    { re: /\b(tor|proxy|vpn|tunnel|socks)\b.{0,20}\b(route|forward|relay|chain)\b/i, conf: 0.5, ev: "Anonymization/tunneling for abuse" },
  ];

  for (const { re, conf, ev } of abusePatterns) {
    if (re.test(input)) {
      signals.push({ source: "abuse-intent", category: "RESOURCE_ABUSE", confidence: conf, evidence: ev, weight: 1.1 });
    }
  }

  return signals;
}

/**
 * Contextual analysis — uses conversation history to detect patterns
 * across turns (not just single-message analysis).
 */
function analyzeConversationContext(
  input: string,
  history?: Array<{ role: string; content: string }>
): IntentSignal[] {
  const signals: IntentSignal[] = [];
  if (!history || history.length === 0) return signals;

  const userMsgs = history.filter((m) => m.role === "user").map((m) => m.content.toLowerCase());
  const allMsgs = [...userMsgs, input.toLowerCase()];

  // Detect progressive boundary testing
  const boundaryKeywords = ["can you", "what if", "try to", "is it possible", "what happens"];
  const sensitiveKeywords = ["root", "admin", "system", "secret", "env", "password", "outside", "external", "escape"];

  let boundaryTestCount = 0;
  for (const msg of allMsgs) {
    const hasBoundary = boundaryKeywords.some((kw) => msg.includes(kw));
    const hasSensitive = sensitiveKeywords.some((kw) => msg.includes(kw));
    if (hasBoundary && hasSensitive) boundaryTestCount++;
  }

  if (boundaryTestCount >= 2) {
    signals.push({
      source: "context-analysis",
      category: "RECONNAISSANCE",
      confidence: Math.min(0.3 + boundaryTestCount * 0.15, 0.85),
      evidence: `${boundaryTestCount} messages contain boundary-testing patterns`,
      weight: 1.3,
    });
  }

  // Detect rapid topic shift from benign to sensitive
  if (allMsgs.length >= 3) {
    const lastThree = allMsgs.slice(-3);
    const devKeywords = ["create", "build", "component", "function", "react", "api", "style", "css", "html"];
    const attackKeywords = ["secret", "env", "password", "root", "admin", "bypass", "disable", "override", "system prompt"];

    const earlyDev = lastThree.slice(0, 2).some((m) => devKeywords.some((kw) => m.includes(kw)));
    const lateAttack = attackKeywords.some((kw) => lastThree[lastThree.length - 1].includes(kw));

    if (earlyDev && lateAttack) {
      signals.push({
        source: "context-analysis",
        category: "SOCIAL_ENGINEERING",
        confidence: 0.6,
        evidence: "Topic shifted from development to security-sensitive in recent turns",
        weight: 1.2,
      });
    }
  }

  return signals;
}

// ── Signal Fusion ─────────────────────────────────────────────────────────

/**
 * Fuses all intent signals into a single classification.
 * Uses weighted voting — highest weighted category wins.
 */
function fuseSignals(signals: IntentSignal[]): IntentClassification {
  if (signals.length === 0) {
    return {
      primaryIntent: "BENIGN_DEV",
      confidence: 0.8,
      signals: [],
      riskScore: 0,
      recommendation: "ALLOW",
      explanation: "No suspicious signals detected",
    };
  }

  // Aggregate scores per category
  const categoryScores: Record<string, number> = {};
  const categoryMaxConf: Record<string, number> = {};

  for (const signal of signals) {
    const cat = signal.category;
    const weighted = signal.confidence * signal.weight;
    categoryScores[cat] = (categoryScores[cat] || 0) + weighted;
    categoryMaxConf[cat] = Math.max(categoryMaxConf[cat] || 0, signal.confidence);
  }

  // Find dominant category
  let primaryIntent: IntentCategory = "BENIGN_DEV";
  let maxScore = 0;

  for (const [cat, score] of Object.entries(categoryScores)) {
    if (cat === "BENIGN_DEV") continue; // Handle benign separately
    if (score > maxScore) {
      maxScore = score;
      primaryIntent = cat as IntentCategory;
    }
  }

  // If benign signal is strong enough, it overrides
  const benignScore = categoryScores["BENIGN_DEV"] || 0;
  if (benignScore > maxScore * 1.5) {
    primaryIntent = "BENIGN_DEV";
    maxScore = benignScore;
  }

  // Compute risk score (0-1)
  const maliciousSignals = signals.filter((s) => s.category !== "BENIGN_DEV");
  // Base risk: sum of weighted confidence across all malicious signals
  let riskScore = Math.min(
    maliciousSignals.reduce((sum, s) => sum + s.confidence * s.weight * 0.3, 0),
    1.0
  );

  // Escalation: if any single signal has high confidence (≥0.8) in a dangerous
  // category, ensure risk score crosses at least the FLAG threshold
  const highConfDangerous = maliciousSignals.filter(
    (s) => s.confidence >= 0.8 &&
    ["PRIVILEGE_ESCALATION", "RESOURCE_ABUSE", "EXFILTRATION", "SABOTAGE"].includes(s.category)
  );
  if (highConfDangerous.length > 0) {
    const maxConf = Math.max(...highConfDangerous.map((s) => s.confidence * s.weight));
    riskScore = Math.max(riskScore, maxConf * 0.75);
  }

  // Multi-signal escalation: 2+ independent malicious categories = amplify
  const uniqueMaliciousCategories = new Set(maliciousSignals.map((s) => s.category));
  if (uniqueMaliciousCategories.size >= 2) {
    riskScore = Math.min(riskScore * 1.3, 1.0);
  }

  // Benign dampening: strong benign signal reduces risk (but never to zero if malicious present)
  // Skip dampening when high-confidence dangerous intent is present — "install xmrig" has
  // "install" (benign) but xmrig (crypto mining) should not be dampened
  const hasClearDangerousIntent = highConfDangerous.length > 0;
  if (benignScore > 0 && maliciousSignals.length > 0 && !hasClearDangerousIntent) {
    const benignDampening = Math.min(benignScore / (benignScore + maxScore + 0.01), 0.4);
    riskScore = riskScore * (1 - benignDampening);
  }

  // Determine recommendation
  let recommendation: IntentClassification["recommendation"] = "ALLOW";
  if (riskScore >= 0.7) recommendation = "BLOCK";
  else if (riskScore >= 0.3) recommendation = "FLAG";

  // Build explanation
  const topSignals = [...signals]
    .filter((s) => s.category !== "BENIGN_DEV")
    .sort((a, b) => b.confidence * b.weight - a.confidence * a.weight)
    .slice(0, 3);

  const explanation =
    primaryIntent === "BENIGN_DEV"
      ? "Input appears to be a normal development request"
      : `Detected ${primaryIntent} intent: ${topSignals.map((s) => s.evidence).join("; ")}`;

  return {
    primaryIntent,
    confidence: categoryMaxConf[primaryIntent] || 0.8,
    signals,
    riskScore,
    recommendation,
    explanation,
  };
}

// ── Utility ───────────────────────────────────────────────────────────────

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Main Entry Point ──────────────────────────────────────────────────────

export function classifyIntent(
  input: string,
  options?: {
    history?: Array<{ role: string; content: string }>;
  }
): IntentClassification {
  const signals: IntentSignal[] = [
    ...analyzeImperativeTarget(input),
    ...analyzeReconIntent(input),
    ...analyzePrivEscIntent(input),
    ...analyzeExfilIntent(input),
    ...analyzeEvasionIntent(input),
    ...analyzeResourceAbuseIntent(input),
    ...analyzeConversationContext(input, options?.history),
  ];

  const classification = fuseSignals(signals);

  if (classification.riskScore > 0.3) {
    logger.warn({
      intent: classification.primaryIntent,
      riskScore: classification.riskScore,
      recommendation: classification.recommendation,
      signalCount: classification.signals.length,
    }, "Elevated intent risk detected");
  }

  return classification;
}
