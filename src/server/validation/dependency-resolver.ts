// Regex-based import extraction (faster than AST for this purpose)

const IMPORT_PATTERNS = [
  // import ... from 'package'
  /import\s+(?:[\w{}\s*,]+)\s+from\s+['"]([^'"./][^'"]*)['"]/g,
  // import 'package' (side-effect)
  /import\s+['"]([^'"./][^'"]*)['"]/g,
  // require('package')
  /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
  // dynamic import('package')
  /import\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
];

function extractBareSpecifier(specifier: string): string {
  // Scoped packages: @scope/package/sub -> @scope/package
  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  // Regular packages: package/sub -> package
  return specifier.split("/")[0];
}

// Built-in Node.js modules to ignore
const NODE_BUILTINS = new Set([
  "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns",
  "events", "fs", "http", "http2", "https", "net", "os", "path", "perf_hooks",
  "process", "querystring", "readline", "repl", "stream", "string_decoder",
  "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib",
  "async_hooks", "console", "constants", "domain", "inspector", "module",
  "punycode", "sys", "trace_events", "wasi",
]);

function isNodeBuiltin(pkg: string): boolean {
  if (NODE_BUILTINS.has(pkg)) return true;
  if (pkg.startsWith("node:")) return true;
  return false;
}

export function findMissingDeps(
  code: string,
  packageJson: Record<string, any>
): string[] {
  const allDeps = new Set<string>([
    ...Object.keys(packageJson.dependencies || {}),
    ...Object.keys(packageJson.devDependencies || {}),
    ...Object.keys(packageJson.peerDependencies || {}),
  ]);

  const importedPackages = new Set<string>();

  for (const pattern of IMPORT_PATTERNS) {
    // Reset regex state
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(code)) !== null) {
      const bare = extractBareSpecifier(match[1]);
      if (!isNodeBuiltin(bare)) {
        importedPackages.add(bare);
      }
    }
  }

  const missing: string[] = [];
  for (const pkg of importedPackages) {
    if (!allDeps.has(pkg)) {
      missing.push(pkg);
    }
  }

  return missing.sort();
}
