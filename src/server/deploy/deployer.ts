import Docker from "dockerode";
import { PrismaClient } from "@prisma/client";
import { detectFramework } from "./framework-detector";
import { generateDockerfile } from "./dockerfile-generator";
import { runPreDeployGate } from "./pre-deploy-gate";
import { execInWorkspace } from "../services/workspace";

const docker = new Docker({ socketPath: "/var/run/docker.sock" });
const prisma = new PrismaClient();

export async function deployProject(projectId: string, userId: string): Promise<{
  deploymentId: string;
  url?: string;
  error?: string;
}> {
  const project = await prisma.project.findUniqueOrThrow({ where: { id: projectId } });
  if (!project.containerName || project.status !== "running") {
    throw new Error("Workspace must be running to deploy");
  }

  // Create deployment record
  const deployment = await prisma.deployment.create({
    data: {
      projectId,
      deployedBy: userId,
      environment: "preview",
      status: "building",
    },
  });

  try {
    // 1. Pre-deploy gate
    const gateResult = await runPreDeployGate(project.containerName);
    if (!gateResult.passed) {
      await prisma.deployment.update({
        where: { id: deployment.id },
        data: {
          status: "failed",
          buildLog: `Pre-deploy gate failed:\n${gateResult.checks
            .filter((c) => !c.passed)
            .map((c) => `  [${c.severity}] ${c.name}: ${c.details}`)
            .join("\n")}`,
        },
      });
      return { deploymentId: deployment.id, error: "Pre-deploy gate failed" };
    }

    // 2. Detect framework
    const framework = await detectFramework(project.containerName);

    // 3. Generate Dockerfile
    const dockerfile = generateDockerfile(framework);
    await execInWorkspace(project.containerName, `cat > /workspace/Dockerfile.deploy << 'DEOF'\n${dockerfile}\nDEOF`);

    // 4. Copy workspace files to build context
    const container = docker.getContainer(project.containerName);
    const archive = await container.getArchive({ path: "/workspace" });

    // 5. Build image
    const imageTag = `deployed-${projectId}:${Date.now()}`;
    const buildStream = await docker.buildImage(archive as any, {
      t: imageTag,
      dockerfile: "workspace/Dockerfile.deploy",
    });

    // Wait for build to complete
    await new Promise<void>((resolve, reject) => {
      docker.modem.followProgress(buildStream, (err: any) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // 6. Start deployed container
    const deployName = `deployed-${projectId}`;

    // Remove old deployment if exists
    try {
      const old = docker.getContainer(deployName);
      await old.stop({ t: 5 }).catch(() => {});
      await old.remove({ force: true }).catch(() => {});
    } catch {}

    const deployContainer = await docker.createContainer({
      Image: imageTag,
      name: deployName,
      Labels: {
        "traefik.enable": "true",
        [`traefik.http.routers.${deployName}.rule`]: `Host(\`${deployName}.localhost\`)`,
        [`traefik.http.routers.${deployName}.entrypoints`]: "web",
        [`traefik.http.services.${deployName}.loadbalancer.server.port`]: "3100",
        "devfactory.type": "deployment",
        "devfactory.project-id": projectId,
      },
      HostConfig: {
        NetworkMode: "devfactory",
        Memory: 512 * 1024 * 1024, // 512MB (deployed apps need less)
        NanoCpus: 1e9, // 1 CPU
      },
    });

    await deployContainer.start();

    const url = `http://${deployName}.localhost`;

    // 7. Update deployment record
    await prisma.deployment.update({
      where: { id: deployment.id },
      data: {
        status: "deployed",
        url,
        containerId: deployContainer.id,
        imageTag,
        buildLog: `Framework: ${framework.name}\nImage: ${imageTag}\nURL: ${url}`,
      },
    });

    return { deploymentId: deployment.id, url };
  } catch (err: any) {
    await prisma.deployment.update({
      where: { id: deployment.id },
      data: { status: "failed", buildLog: err.message },
    });
    return { deploymentId: deployment.id, error: err.message };
  }
}
