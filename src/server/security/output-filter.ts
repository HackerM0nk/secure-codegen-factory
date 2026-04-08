// src/server/security/output-filter.ts
// Post-LLM command denylist engine: sits between LLM output and shell_exec

export interface CommandContext {
  projectId: string;
  userId: string;
  conversationTurn: number;
  containerName: string;
  workspacePrefix?: string;
}

export interface CommandLogEntry {
  command: string;
  args: string;
  timestamp: string;
  projectId: string;
  userId: string;
  conversationTurn: number;
  verdict: "BLOCK" | "ALERT" | "PASS";
  pattern?: string;
}

export interface FilterResult {
  allowed: boolean;
  verdict: "BLOCK" | "ALERT" | "PASS";
  pattern?: string;
  message?: string;
  logEntry: CommandLogEntry;
}

// ── BLOCK patterns ─────────────────────────────────────────────────────────

const BLOCK_PATTERNS: Array<{ name: string; regex: RegExp; description: string }> = [
  // Pipe-to-shell
  { name: "curl_pipe_bash", regex: /curl\s.*\|\s*(ba)?sh/i, description: "piping curl to shell" },
  { name: "wget_pipe_sh", regex: /wget\s.*\|\s*(ba)?sh/i, description: "piping wget to shell" },
  { name: "curl_pipe_shell", regex: /curl\s.*\|\s*\/bin\/(ba)?sh/i, description: "piping curl to shell binary" },

  // Dev TCP/UDP
  { name: "dev_tcp", regex: /\/dev\/tcp\//i, description: "/dev/tcp access" },
  { name: "dev_udp", regex: /\/dev\/udp\//i, description: "/dev/udp access" },

  // Reverse shells
  { name: "bash_reverse_shell", regex: /bash\s+-i\s+>&\s*\/dev\/tcp\//i, description: "bash reverse shell" },
  { name: "nc_reverse_shell", regex: /\bnc\s+-e\s*\/bin\//i, description: "nc reverse shell" },
  { name: "ncat_reverse_shell", regex: /\bncat\s+-e\b/i, description: "ncat reverse shell" },
  { name: "socat_exec", regex: /\bsocat\b.*\bEXEC\b/i, description: "socat exec" },
  { name: "python_socket_connect", regex: /python[23]?\s+-c\s+.*socket.*connect/i, description: "python socket reverse shell" },

  // Base64 exec chains
  { name: "base64_pipe_bash", regex: /echo\s.*\|\s*base64\s.*-d\s*\|\s*(ba)?sh/i, description: "base64 decode piped to shell" },
  { name: "base64_pipe_shell", regex: /base64\s+-d\s*\|\s*(ba)?sh/i, description: "base64 decode piped to shell" },

  // Eval injection
  { name: "eval_subshell", regex: /eval\s*\$\(/i, description: "eval with command substitution" },
  { name: "eval_double_quote_subshell", regex: /eval\s+"\$\(/i, description: "eval with quoted command substitution" },
  { name: "eval_backtick", regex: /eval\s+`/i, description: "eval with backtick substitution" },
  { name: "curl_subshell_exec", regex: /\$\(\s*curl\b/i, description: "curl in command substitution" },

  // Destructive
  { name: "rm_rf_root", regex: /rm\s+-rf\s+\/(?!\w)/i, description: "rm -rf /" },
  { name: "rm_rf_root_var", regex: /rm\s+-rf\s+\/\s/i, description: "rm -rf root" },

  // System path writes
  { name: "write_etc", regex: />\s*\/etc\//i, description: "writing to /etc" },
  { name: "append_etc", regex: />>\s*\/etc\//i, description: "appending to /etc" },
  { name: "tee_etc", regex: /tee\s+\/etc\//i, description: "tee to /etc" },
  { name: "write_proc", regex: />\s*\/proc\//i, description: "writing to /proc" },
  { name: "write_sys", regex: />\s*\/sys\//i, description: "writing to /sys" },

  // Container escape
  { name: "nsenter", regex: /\bnsenter\b/i, description: "nsenter (container escape)" },
  { name: "unshare_escape", regex: /\bunshare\b/i, description: "unshare (container escape)" },
  { name: "chroot", regex: /\bchroot\b/i, description: "chroot (container escape)" },
  { name: "docker_sock", regex: /docker\.sock/i, description: "docker socket access" },

  // Cloud metadata SSRF
  { name: "metadata_ssrf", regex: /169\.254\.169\.254/i, description: "cloud metadata endpoint SSRF" },
  { name: "metadata_ssrf_v6", regex: /\[fd00:ec2::254\]/i, description: "cloud metadata IPv6 SSRF" },

  // K8s service account token
  { name: "k8s_sa_token", regex: /\/var\/run\/secrets\/kubernetes/i, description: "K8s service account token access" },
  { name: "k8s_sa_token_alt", regex: /serviceaccount\/token/i, description: "K8s service account token" },

  // Sensitive file reads
  { name: "etc_shadow", regex: /\bcat\s+\/etc\/shadow\b/i, description: "/etc/shadow read" },
  { name: "etc_passwd_read", regex: /\bcat\s+\/etc\/passwd\b/i, description: "/etc/passwd read" },
  { name: "read_proc_environ", regex: /\/proc\/.*\/environ/i, description: "process environment read (credential exfil)" },
  { name: "read_proc_self", regex: /\/proc\/self\/(maps|status|cmdline|mountinfo)/i, description: "sensitive /proc/self read" },
  { name: "read_docker_env", regex: /\bprintenv\b|\benv\b.*>\s|export\s.*>|set\s*\|/i, description: "environment variable dump" },
];

// ── ALERT patterns ─────────────────────────────────────────────────────────

const ALERT_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "chmod_777", regex: /chmod\s+777\b/ },
  { name: "chmod_setuid", regex: /chmod\s+\+s\b/ },
  { name: "chmod_u_setuid", regex: /chmod\s+u\+s\b/ },
  { name: "ssh_keygen", regex: /\bssh-keygen\b/ },
  { name: "ssh_copy_id", regex: /\bssh-copy-id\b/ },
  { name: "crontab", regex: /\bcrontab\b/ },
  { name: "at_command", regex: /\bat\s+-f\b/ },
  { name: "systemctl", regex: /\bsystemctl\b/ },
  { name: "useradd", regex: /\buseradd\b/ },
  { name: "passwd", regex: /\bpasswd\b/ },
  { name: "adduser", regex: /\badduser\b/ },
  { name: "iptables", regex: /\biptables\b/ },
  { name: "ip_route", regex: /\bip\s+route\b/ },
  { name: "sus_port_4444", regex: /\b(curl|wget|nc|ncat)\b.*\b4444\b/ },
  { name: "sus_port_1337", regex: /\b(curl|wget|nc|ncat)\b.*\b1337\b/ },
  { name: "sus_port_8888", regex: /\b(curl|wget|nc|ncat)\b.*\b8888\b/ },
  { name: "sus_port_9001", regex: /\b(curl|wget|nc|ncat)\b.*\b9001\b/ },
];

// ── In-memory log buffer ───────────────────────────────────────────────────

const LOG_BUFFER: CommandLogEntry[] = [];
const MAX_LOG_SIZE = 10000;

export function getSecurityLogs(): ReadonlyArray<CommandLogEntry> {
  return LOG_BUFFER;
}

export function getSecurityStats(): {
  totalBlocks: number;
  totalAlerts: number;
  totalPass: number;
  topBlockedPatterns: Array<{ pattern: string; count: number }>;
} {
  let totalBlocks = 0;
  let totalAlerts = 0;
  let totalPass = 0;
  const patternCounts = new Map<string, number>();

  for (const entry of LOG_BUFFER) {
    switch (entry.verdict) {
      case "BLOCK":
        totalBlocks++;
        if (entry.pattern) {
          patternCounts.set(entry.pattern, (patternCounts.get(entry.pattern) || 0) + 1);
        }
        break;
      case "ALERT":
        totalAlerts++;
        break;
      case "PASS":
        totalPass++;
        break;
    }
  }

  const topBlockedPatterns = Array.from(patternCounts.entries())
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return { totalBlocks, totalAlerts, totalPass, topBlockedPatterns };
}

// Security event callback type
export type SecurityEventCallback = (event: {
  level: "BLOCK" | "ALERT" | "INFO";
  entry: CommandLogEntry;
}) => void;

let securityEventCallback: SecurityEventCallback | null = null;

export function setSecurityEventCallback(cb: SecurityEventCallback): void {
  securityEventCallback = cb;
}

function logCommand(entry: CommandLogEntry): void {
  LOG_BUFFER.push(entry);
  if (LOG_BUFFER.length > MAX_LOG_SIZE) {
    LOG_BUFFER.splice(0, LOG_BUFFER.length - MAX_LOG_SIZE);
  }
  if (securityEventCallback && entry.verdict !== "PASS") {
    securityEventCallback({ level: entry.verdict, entry });
  }
}

// ── Public API ──────────────────────────────────────────────────────────────

export function filterCommand(command: string, context: CommandContext): FilterResult {
  const timestamp = new Date().toISOString();
  const baseEntry: Omit<CommandLogEntry, "verdict" | "pattern"> = {
    command: command.substring(0, 500),
    args: "",
    timestamp,
    projectId: context.projectId,
    userId: context.userId,
    conversationTurn: context.conversationTurn,
  };

  // Check BLOCK patterns
  for (const { name, regex, description } of BLOCK_PATTERNS) {
    if (regex.test(command)) {
      const entry: CommandLogEntry = { ...baseEntry, verdict: "BLOCK", pattern: name };
      logCommand(entry);
      return {
        allowed: false,
        verdict: "BLOCK",
        pattern: name,
        message: `Command blocked by security policy: ${name}. This command is not allowed in the workspace. Try an alternative approach that doesn't use ${description}.`,
        logEntry: entry,
      };
    }
  }

  // Check ALERT patterns
  for (const { name, regex } of ALERT_PATTERNS) {
    if (regex.test(command)) {
      const entry: CommandLogEntry = { ...baseEntry, verdict: "ALERT", pattern: name };
      logCommand(entry);
      return {
        allowed: true,
        verdict: "ALERT",
        pattern: name,
        logEntry: entry,
      };
    }
  }

  // PASS
  const entry: CommandLogEntry = { ...baseEntry, verdict: "PASS" };
  logCommand(entry);
  return {
    allowed: true,
    verdict: "PASS",
    logEntry: entry,
  };
}
