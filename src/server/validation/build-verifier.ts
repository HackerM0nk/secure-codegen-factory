import { execSync } from "child_process";

export interface BuildVerification {
  buildPassed: boolean;
  serverResponding: boolean;
  buildOutput: string;
  errors: string[];
}

const BUILD_TIMEOUT_MS = 60_000;
const HEALTH_CHECK_RETRIES = 5;
const HEALTH_CHECK_DELAY_MS = 2_000;

function dockerExec(containerName: string, cmd: string, timeoutMs: number): string {
  try {
    const result = execSync(
      `docker exec ${containerName} sh -c "${cmd.replace(/"/g, '\\"')}"`,
      {
        timeout: timeoutMs,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      }
    );
    return result;
  } catch (err: any) {
    // execSync throws on non-zero exit, but stderr is in err.stderr
    return err.stdout || err.stderr || err.message || "";
  }
}

function parseBuildErrors(output: string): string[] {
  const errors: string[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    // TypeScript errors: TS2304, TS2322, etc.
    if (/TS\d{4}:/.test(trimmed)) {
      errors.push(trimmed);
    }
    // Module not found
    if (trimmed.includes("Module not found") || trimmed.includes("Cannot find module")) {
      errors.push(trimmed);
    }
    // SyntaxError
    if (trimmed.includes("SyntaxError")) {
      errors.push(trimmed);
    }
    // Generic "error" lines from bundlers
    if (/^error\b/i.test(trimmed) || /^ERROR\b/.test(trimmed)) {
      errors.push(trimmed);
    }
  }

  return errors;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function verify(containerName: string): Promise<BuildVerification> {
  // 1. Run build
  const buildOutput = dockerExec(
    containerName,
    "cd /workspace && npm run build 2>&1",
    BUILD_TIMEOUT_MS
  );

  const errors = parseBuildErrors(buildOutput);
  const buildPassed = errors.length === 0 && !buildOutput.includes("Build failed");

  let serverResponding = false;

  // 2. If build passed, check server health
  if (buildPassed) {
    for (let i = 0; i < HEALTH_CHECK_RETRIES; i++) {
      try {
        const result = dockerExec(
          containerName,
          "curl -sf http://localhost:3000 -o /dev/null && echo OK",
          10_000
        );
        if (result.includes("OK")) {
          serverResponding = true;
          break;
        }
      } catch {
        // Retry
      }
      await sleep(HEALTH_CHECK_DELAY_MS);
    }
  }

  return {
    buildPassed,
    serverResponding,
    buildOutput,
    errors,
  };
}
