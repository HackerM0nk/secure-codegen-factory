// src/server/services/snapshot.ts
// Content-addressed snapshot service with integrity verification

import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { createHash } from "crypto";
import { Readable } from "stream";
import * as tar from "tar-stream";
import { execInWorkspace, docker } from "./docker";
import { createLogger } from "../observability/logger";

const logger = createLogger("snapshot");

// ── S3 client setup ───────────────────────────────────────────────────────

const S3_ENDPOINT = process.env.S3_ENDPOINT || "http://localhost:4666";

const s3 = new S3Client({
  region: process.env.AWS_REGION || "us-east-1",
  endpoint: S3_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "test",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "test",
  },
});

const BUCKET = process.env.S3_BUCKET || "workspace-snapshots";

// ── Content-addressed key generation ──────────────────────────────────────

function computeSHA256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function buildSnapshotKey(projectId: string, contentHash: string): string {
  // Format: <projectId>/<sha256>.tar.gz
  return `${projectId}/${contentHash}.tar.gz`;
}

// ── Docker archive helpers ────────────────────────────────────────────────
// Docker's getArchive() returns a tar stream that WRAPS the requested file.
// We need to extract the inner file from that tar envelope.

async function extractInnerFile(dockerArchiveStream: NodeJS.ReadableStream): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const extract = tar.extract();
    const chunks: Buffer[] = [];

    extract.on("entry", (_header, stream, next) => {
      stream.on("data", (chunk: Buffer) => chunks.push(chunk));
      stream.on("end", next);
    });

    extract.on("finish", () => resolve(Buffer.concat(chunks)));
    extract.on("error", reject);

    (dockerArchiveStream as NodeJS.ReadableStream).pipe(extract);
  });
}

// Docker's putArchive() expects a tar stream, not raw file content.
// Wrap the file in a single-entry tar so Docker extracts it correctly.

async function wrapInTar(content: Buffer, filename: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const pack = tar.pack();
    pack.entry({ name: filename }, content);
    pack.finalize();

    const chunks: Buffer[] = [];
    pack.on("data", (chunk: Buffer) => chunks.push(chunk));
    pack.on("end", () => resolve(Buffer.concat(chunks)));
    pack.on("error", reject);
  });
}

// ── Public API ────────────────────────────────────────────────────────────

export interface SnapshotResult {
  snapshotKey: string;
  snapshotHash: string;
  sizeBytes: number;
}

export async function saveSnapshot(
  containerName: string,
  projectId: string
): Promise<SnapshotResult> {
  const start = Date.now();

  // Create tar of workspace excluding heavy dirs
  await execInWorkspace(
    containerName,
    "cd /workspace && tar czf /tmp/snapshot.tar.gz --exclude=node_modules --exclude=.git --exclude=dist ."
  );

  // Get tar from container — Docker getArchive returns a tar wrapping the file,
  // so we must extract the inner snapshot.tar.gz from the Docker tar envelope.
  const container = docker.getContainer(containerName);
  const stream = await container.getArchive({ path: "/tmp/snapshot.tar.gz" });

  const tarBuffer = await extractInnerFile(stream);

  // Compute content-addressed hash (SHA256 of the tar content)
  const contentHash = computeSHA256(tarBuffer);
  const snapshotKey = buildSnapshotKey(projectId, contentHash);

  // Check if this exact snapshot already exists (deduplication)
  try {
    await s3.send(
      new HeadObjectCommand({ Bucket: BUCKET, Key: snapshotKey })
    );
    // Already exists -- skip upload
    logger.info(
      { projectId, snapshotKey, contentHash, sizeBytes: tarBuffer.length },
      "Snapshot already exists (deduplicated), skipping upload"
    );
    return {
      snapshotKey,
      snapshotHash: contentHash,
      sizeBytes: tarBuffer.length,
    };
  } catch (e: any) {
    if (e.name !== "NotFound" && e.$metadata?.httpStatusCode !== 404) {
      // Unexpected error, log but continue with upload
      logger.warn({ error: e.message }, "HeadObject check failed, proceeding with upload");
    }
  }

  // Upload with content hash as metadata for integrity verification
  await s3.send(
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: snapshotKey,
      Body: tarBuffer,
      ContentType: "application/gzip",
      Metadata: {
        "content-hash": contentHash,
        "project-id": projectId,
        "created-at": new Date().toISOString(),
      },
    })
  );

  const durationMs = Date.now() - start;
  logger.info(
    { projectId, snapshotKey, contentHash, sizeBytes: tarBuffer.length, durationMs },
    "Snapshot saved"
  );

  return {
    snapshotKey,
    snapshotHash: contentHash,
    sizeBytes: tarBuffer.length,
  };
}

export async function restoreSnapshot(
  containerName: string,
  snapshotKey: string,
  expectedHash?: string
): Promise<{ verified: boolean; durationMs: number }> {
  const start = Date.now();

  logger.info({ containerName, snapshotKey, expectedHash }, "Restoring snapshot");

  const response = await s3.send(
    new GetObjectCommand({ Bucket: BUCKET, Key: snapshotKey })
  );

  // Read the full body for integrity verification
  const bodyStream = response.Body as Readable;
  const chunks: Buffer[] = [];
  for await (const chunk of bodyStream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  const tarBuffer = Buffer.concat(chunks);

  // ── Integrity verification ──────────────────────────────────────────────
  const actualHash = computeSHA256(tarBuffer);
  let verified = true;

  if (expectedHash) {
    if (actualHash !== expectedHash) {
      logger.error(
        { snapshotKey, expectedHash, actualHash },
        "Snapshot integrity verification FAILED"
      );
      throw new Error(
        `Snapshot integrity verification failed: expected ${expectedHash}, got ${actualHash}`
      );
    }
    logger.info({ snapshotKey, hash: actualHash }, "Snapshot integrity verified");
  } else {
    // Check against S3 metadata if no expected hash provided
    const metadataHash = response.Metadata?.["content-hash"];
    if (metadataHash && metadataHash !== actualHash) {
      logger.error(
        { snapshotKey, metadataHash, actualHash },
        "Snapshot integrity verification against S3 metadata FAILED"
      );
      throw new Error(
        `Snapshot integrity verification failed: metadata hash ${metadataHash}, actual ${actualHash}`
      );
    }
    if (!metadataHash) {
      logger.warn(
        { snapshotKey },
        "No expected hash provided and no metadata hash found, skipping integrity check"
      );
      verified = false;
    }
  }

  // ── Restore to container ────────────────────────────────────────────────
  // NOTE: This is the Docker-specific restore path. A K8s implementation would
  // use kubectl cp or direct S3 streaming to the pod volume instead.
  const container = docker.getContainer(containerName);

  // Docker putArchive expects a tar stream, so wrap the raw .tar.gz in a tar
  // with the correct filename. putArchive extracts to the target path, placing
  // snapshot.tar.gz at /tmp/snapshot.tar.gz.
  const wrappedTar = await wrapInTar(tarBuffer, "snapshot.tar.gz");

  const readableBuffer = new Readable({
    read() {
      this.push(wrappedTar);
      this.push(null);
    },
  });

  await container.putArchive(readableBuffer, { path: "/tmp" });

  // Extract the snapshot into the workspace
  await execInWorkspace(
    containerName,
    "cd /workspace && tar xzf /tmp/snapshot.tar.gz"
  );

  // Reinstall dependencies
  await execInWorkspace(
    containerName,
    "cd /workspace && npm install --prefer-offline 2>/dev/null || true"
  );

  const durationMs = Date.now() - start;
  logger.info(
    { containerName, snapshotKey, verified, durationMs },
    "Snapshot restored"
  );

  return { verified, durationMs };
}

// ── Utility: Verify a snapshot without restoring ──────────────────────────

export async function verifySnapshot(
  snapshotKey: string,
  expectedHash: string
): Promise<{ valid: boolean; actualHash: string }> {
  const response = await s3.send(
    new GetObjectCommand({ Bucket: BUCKET, Key: snapshotKey })
  );

  const bodyStream = response.Body as Readable;
  const chunks: Buffer[] = [];
  for await (const chunk of bodyStream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  const tarBuffer = Buffer.concat(chunks);
  const actualHash = computeSHA256(tarBuffer);

  return {
    valid: actualHash === expectedHash,
    actualHash,
  };
}
