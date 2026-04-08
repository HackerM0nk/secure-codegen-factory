import { readFileFromWorkspace, execInWorkspace } from "../services/workspace";

export interface DetectedFramework {
  name: string;
  buildCommand: string;
  startCommand: string;
  defaultPort: number;
  outputDir: string;
}

const FRAMEWORKS: Record<string, DetectedFramework> = {
  nextjs: {
    name: "Next.js",
    buildCommand: "npm run build",
    startCommand: "npm start",
    defaultPort: 3100,
    outputDir: ".next",
  },
  vite: {
    name: "Vite (React/Vue)",
    buildCommand: "npm run build",
    startCommand: "npx serve dist -l 3100",
    defaultPort: 3100,
    outputDir: "dist",
  },
  express: {
    name: "Express.js",
    buildCommand: "npm run build || true",
    startCommand: "node dist/index.js || node src/index.js",
    defaultPort: 3100,
    outputDir: "dist",
  },
  static: {
    name: "Static HTML",
    buildCommand: "true",
    startCommand: "npx serve . -l 3100",
    defaultPort: 3100,
    outputDir: ".",
  },
};

export async function detectFramework(containerName: string): Promise<DetectedFramework> {
  try {
    const pkgJson = await readFileFromWorkspace(containerName, "/workspace/package.json");
    const pkg = JSON.parse(pkgJson);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    if (deps["next"]) return FRAMEWORKS.nextjs;
    if (deps["vite"]) return FRAMEWORKS.vite;
    if (deps["express"] || deps["fastify"] || deps["koa"]) return FRAMEWORKS.express;
  } catch {}

  // Check for Python
  try {
    await readFileFromWorkspace(containerName, "/workspace/requirements.txt");
    return {
      name: "Python",
      buildCommand: "pip install -r requirements.txt",
      startCommand: "python app.py",
      defaultPort: 5000,
      outputDir: ".",
    };
  } catch {}

  return FRAMEWORKS.static;
}
