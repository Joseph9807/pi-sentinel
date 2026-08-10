import { createHash } from "node:crypto";
import { appendFile, mkdir, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import type { RiskLevel } from "./judge.ts";

export const AUDIT_FILE = "sentinel-audit.jsonl";
export const MAX_AUDIT_BYTES = 1024 * 1024;
const MAX_PREVIEW_LENGTH = 1_024;
const REDACTED = "[REDACTED]";

export interface AuditEvent {
  timestamp: string;
  workingDirectory: string;
  toolName: string;
  arguments: Record<string, unknown>;
  riskLevel: RiskLevel;
  operationSummary: string;
  riskExplanation: string;
  decisionSource: "ai-judge" | "hard-guard" | "human" | "runtime";
  outcome: "allowed" | "approval-required" | "denied" | "timeout" | "judge-error";
  modelIdentifier: string;
  judgeLatencyMs?: number;
}

let writes = Promise.resolve();

export function writeAuditEvent(event: AuditEvent, directory: string): Promise<void> {
  const pending = writes.then(() => writeToDisk(event, directory));
  writes = pending.catch(() => undefined);
  return pending;
}

async function writeToDisk(event: AuditEvent, directory: string): Promise<void> {
  const redactedArguments = redact(event.arguments);
  const serializedArguments = JSON.stringify(redactedArguments);
  const { arguments: _arguments, ...fields } = event;
  const line = `${JSON.stringify({
    ...fields,
    argumentPreview: serializedArguments.slice(0, MAX_PREVIEW_LENGTH),
    argumentHash: createHash("sha256").update(serializedArguments).digest("hex"),
  })}\n`;
  const bytes = Buffer.byteLength(line);
  if (bytes > MAX_AUDIT_BYTES) throw new Error("Audit Event exceeds the active file size limit");

  await mkdir(directory, { recursive: true });
  const active = join(directory, AUDIT_FILE);
  await withLock(active, async () => {
    if ((await fileSize(active)) + bytes > MAX_AUDIT_BYTES) await rotate(active);
    await appendFile(active, line, { encoding: "utf8", mode: 0o600 });
  });
}

async function withLock(active: string, action: () => Promise<void>): Promise<void> {
  const lock = `${active}.lock`;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await mkdir(lock);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (await isStaleLock(lock)) await rm(lock, { recursive: true, force: true });
      else await setTimeout(10);
      continue;
    }
    try {
      await action();
    } finally {
      await rm(lock, { recursive: true, force: true });
    }
    return;
  }
  throw new Error("Timed out waiting for the audit trail lock");
}

async function isStaleLock(lock: string): Promise<boolean> {
  try {
    return Date.now() - (await stat(lock)).mtimeMs > 30_000;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function rotate(active: string): Promise<void> {
  await rm(`${active}.2`, { force: true });
  await moveIfPresent(`${active}.1`, `${active}.2`);
  await moveIfPresent(active, `${active}.1`);
}

async function moveIfPresent(from: string, to: string): Promise<void> {
  try {
    await rename(from, to);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function fileSize(path: string): Promise<number> {
  try {
    return (await stat(path)).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw error;
  }
}

function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, isSensitiveKey(key) ? REDACTED : redact(child)]),
  );
}

function isSensitiveKey(key: string): boolean {
  return /password|token|key|secret|authorization|authentication/i.test(key);
}
