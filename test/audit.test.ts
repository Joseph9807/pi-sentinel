import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AUDIT_FILE, MAX_AUDIT_BYTES, writeAuditEvent } from "../src/audit.ts";

const event = {
  timestamp: "2026-08-10T00:00:00.000Z",
  workingDirectory: "/workspace",
  toolName: "custom_tool",
  arguments: {
    password: "hunter2",
    nested: { apiKey: "abc123", authorizationHeader: "Bearer 123", safe: "visible" },
    list: [{ access_token: "token-value", private_key: "key-value", secretValue: "secret-value", authenticationCredential: "auth-value" }],
    payload: "x".repeat(2_000),
  },
  riskLevel: "medium" as const,
  operationSummary: "Publish an artifact",
  riskExplanation: "This changes external state.",
  decisionSource: "ai-judge" as const,
  outcome: "allowed" as const,
  modelIdentifier: "provider/model",
  judgeLatencyMs: 12,
};

test("audit storage redacts recursively, bounds previews, and hashes redacted arguments", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-audit-"));
  await writeAuditEvent(event, directory);

  const stored = JSON.parse((await readFile(join(directory, AUDIT_FILE), "utf8")).trim());
  assert.equal(stored.arguments, undefined);
  assert.ok(stored.argumentPreview.length <= 1_024);
  assert.match(stored.argumentPreview, /\[REDACTED\]/);
  assert.match(stored.argumentPreview, /visible/);
  assert.doesNotMatch(stored.argumentPreview, /hunter2|abc123|Bearer 123|token-value|key-value|secret-value|auth-value/);
  assert.equal(stored.argumentHash, "5e135ae9bb94fb2bf9ed2fbd880d27e1e10719bdccc2a5e85484e0780027c810");

  const sameArguments = { ...event, timestamp: "2026-08-10T00:00:01.000Z" };
  await writeAuditEvent(sameArguments, directory);
  const records = (await readFile(join(directory, AUDIT_FILE), "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(records[0].argumentHash, records[1].argumentHash);
});

test("audit storage keeps one 1MB active file and two valid rotated JSONL files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-rotation-"));
  const path = join(directory, AUDIT_FILE);

  for (let rotation = 0; rotation < 3; rotation++) {
    await writeFile(path, `${JSON.stringify({ generation: rotation, padding: "x".repeat(MAX_AUDIT_BYTES - 60) })}\n`);
    await writeAuditEvent({ ...event, arguments: { generation: rotation } }, directory);
  }

  for (const suffix of ["", ".1", ".2"]) {
    const file = `${path}${suffix}`;
    assert.ok((await stat(file)).size <= MAX_AUDIT_BYTES);
    for (const line of (await readFile(file, "utf8")).trim().split("\n")) assert.doesNotThrow(() => JSON.parse(line));
  }
  await assert.rejects(stat(`${path}.3`));
});

test("audit write failures are reported to the caller", async () => {
  const file = join(await mkdtemp(join(tmpdir(), "sentinel-audit-failure-")), "not-a-directory");
  await writeFile(file, "occupied");
  await assert.rejects(writeAuditEvent(event, file));
});
