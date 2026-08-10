import assert from "node:assert/strict";
import { mkdtemp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { AuditEvent } from "../src/audit.ts";
import { approveToolCall, type ApprovalUI } from "../src/pipeline.ts";

function ui(choices: string[] = [], instructions: string[] = []) {
  const prompts: string[] = [];
  const notifications: string[] = [];
  const value: ApprovalUI = {
    async select(title) {
      prompts.push(title);
      return choices.shift();
    },
    async input() {
      return instructions.shift();
    },
    notify(message) {
      notifications.push(message);
    },
  };
  return { value, prompts, notifications };
}

test("the approval pipeline exposes safe, candidate, and hard-guard behavior", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-pipeline-"));
  const safeUi = ui();
  assert.deepEqual(
    await approveToolCall({ toolName: "read", input: { path: "README.md" } }, { workspace, mode: "tui", ui: safeUi.value }),
    {},
  );
  assert.equal(safeUi.prompts.length, 0);
  assert.deepEqual(
    await approveToolCall({ toolName: "bash", input: { command: "git status --short" } }, { workspace, mode: "tui", ui: safeUi.value }),
    {},
  );
  assert.deepEqual(
    await approveToolCall({ toolName: "write", input: { path: "src/new.ts" } }, { workspace, mode: "tui", ui: safeUi.value }),
    {},
  );

  const denied = ui(["Deny with instructions"], ["Keep the file inside the workspace"]);
  const result = await approveToolCall(
    { toolName: "write", input: { path: join(workspace, "..", "outside.txt") } },
    { workspace, mode: "rpc", ui: denied.value },
  );
  assert.match(result.reason ?? "", /User instruction: Keep the file inside the workspace/);
  assert.match(denied.prompts[0], /Operation: Write/);
  assert.match(denied.prompts[0], /Risk:/);

  const hardUi = ui(["Deny"]);
  const hard = await approveToolCall(
    { toolName: "bash", input: { command: "git reset --hard" } },
    {
      workspace,
      mode: "tui",
      ui: hardUi.value,
      assess: async () => ({ riskLevel: "low", operation: "Harmless", riskExplanation: "None" }),
    },
  );
  assert.equal(hard.block, true);
  assert.match(hardUi.prompts[0], /Discard Git working data/);

  const nonInteractive = await approveToolCall(
    { toolName: "custom_tool", input: {} },
    { workspace, mode: "json", ui: ui().value },
  );
  assert.match(nonInteractive.reason ?? "", /requiring Approval in json mode/);
});

test("risk assessments can allow candidates but cannot downgrade Hard Guards", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-assessment-"));
  const lowUi = ui();
  assert.deepEqual(
    await approveToolCall(
      { toolName: "bash", input: { command: "npm --version" } },
      {
        workspace,
        mode: "tui",
        ui: lowUi.value,
        assess: async () => ({ riskLevel: "low", operation: "Read npm version", riskExplanation: "No state is changed." }),
      },
    ),
    {},
  );
  assert.equal(lowUi.notifications.length, 0);
  assert.equal(lowUi.prompts.length, 0);

  const mediumUi = ui();
  const result = await approveToolCall(
    { toolName: "bash", input: { command: "npm test" } },
    {
      workspace,
      mode: "tui",
      ui: mediumUi.value,
      assess: async () => ({
        riskLevel: "medium",
        operation: "Run tests",
        riskExplanation: "Tests may write temporary files.",
      }),
    },
  );
  assert.deepEqual(result, {});
  assert.equal(mediumUi.notifications.length, 1);
  assert.equal(mediumUi.prompts.length, 0);
});

test("Approval choices and assessment failure fail closed", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-choices-"));
  assert.deepEqual(
    await approveToolCall(
      { toolName: "bash", input: { command: "git reset --hard" } },
      { workspace, mode: "tui", ui: ui(["Allow once"]).value },
    ),
    {},
  );
  assert.equal(
    (
      await approveToolCall(
        { toolName: "custom_tool", input: {} },
        { workspace, mode: "rpc", ui: ui().value },
      )
    ).block,
    true,
  );
  const failed = await approveToolCall(
    { toolName: "bash", input: { command: "npm test" } },
    {
      workspace,
      mode: "print",
      ui: ui().value,
      assess: async () => {
        throw new Error("unavailable");
      },
    },
  );
  assert.match(failed.reason ?? "", /Risk assessment failed/);
});

test("the AI Judge receives bounded context and calibrates Candidate Operations", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-judge-"));
  const seen: unknown[] = [];
  const judge = async (input: Parameters<NonNullable<Parameters<typeof approveToolCall>[1]["assess"]>>[0]) => {
    seen.push(input);
    const command = String(input.call.input.command);
    if (command.includes("node_modules") || command.includes("sudo npm")) {
      return { riskLevel: "medium" as const, operation: "Run a routine package operation", riskExplanation: "The change is recoverable." };
    }
    return { riskLevel: "high" as const, operation: "Delete a user document", riskExplanation: "The file is outside the Workspace." };
  };

  for (const command of ["rm -rf node_modules", "sudo npm install -g typescript"]) {
    const candidateUi = ui();
    assert.deepEqual(
      await approveToolCall(
        { toolName: "bash", input: { command } },
        {
          workspace,
          mode: "tui",
          ui: candidateUi.value,
          tool: { description: "Run a shell command", parameters: { type: "object" } },
          userRequest: "Install and maintain this project",
          assess: judge,
        },
      ),
      {},
    );
    assert.equal(candidateUi.notifications.length, 1);
    assert.equal(candidateUi.prompts.length, 0);
  }

  const externalUi = ui(["Deny"]);
  assert.equal(
    (
      await approveToolCall(
        { toolName: "bash", input: { command: "rm -f /Users/example/Documents/report.docx" } },
        {
          workspace,
          mode: "tui",
          ui: externalUi.value,
          tool: { description: "Run a shell command", parameters: { type: "object" } },
          userRequest: "Clean generated files",
          assess: judge,
        },
      )
    ).block,
    true,
  );
  assert.equal(externalUi.prompts.length, 1);
  assert.deepEqual(seen[0], {
    call: { toolName: "bash", input: { command: "rm -rf node_modules" } },
    tool: { description: "Run a shell command", parameters: { type: "object" } },
    workspace: await realpath(workspace),
    userRequest: "Install and maintain this project",
  });
});

test("judge cancellation and malformed assessments use the same failure path", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-failure-"));
  for (const assess of [
    async () => ({ riskLevel: "uncertain", operation: "Unknown", riskExplanation: "Unknown" }),
    async (_input: unknown, signal: AbortSignal) => {
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      throw signal.reason;
    },
  ]) {
    const controller = new AbortController();
    if (assess.length > 1) queueMicrotask(() => controller.abort());
    const failedUi = ui(["Deny"]);
    const result = await approveToolCall(
      { toolName: "custom_tool", input: { payload: "data" } },
      {
        workspace,
        mode: "rpc",
        ui: failedUi.value,
        signal: controller.signal,
        assess: assess as NonNullable<Parameters<typeof approveToolCall>[1]["assess"]>,
      },
    );
    assert.equal(result.block, true);
    assert.match(failedUi.prompts[0], /Risk assessment failed/);
  }
});

test("the pipeline audits meaningful decisions but not Safe Bypasses", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-events-"));
  const events: AuditEvent[] = [];
  const audit = async (event: AuditEvent) => { events.push(event); };
  const assess = async (riskLevel: "low" | "medium" | "high") => ({
    riskLevel,
    operation: `${riskLevel} operation`,
    riskExplanation: `${riskLevel} explanation`,
  });

  await approveToolCall({ toolName: "read", input: { path: "README.md" } }, { workspace, mode: "tui", ui: ui().value, audit });
  assert.equal(events.length, 0);

  for (const riskLevel of ["low", "medium"] as const) {
    await approveToolCall(
      { toolName: "custom_tool", input: { password: "hidden", value: riskLevel } },
      { workspace, mode: "tui", ui: ui().value, audit, modelIdentifier: "provider/model", assess: () => assess(riskLevel) },
    );
  }
  await approveToolCall(
    { toolName: "custom_tool", input: { value: "high" } },
    { workspace, mode: "tui", ui: ui(["Allow once"]).value, audit, assess: () => assess("high") },
  );
  await approveToolCall(
    { toolName: "custom_tool", input: { value: "denied" } },
    { workspace, mode: "tui", ui: ui(["Deny"]).value, audit, assess: () => assess("high") },
  );
  await approveToolCall(
    { toolName: "bash", input: { command: "git reset --hard" } },
    { workspace, mode: "tui", ui: ui(["Deny"]).value, audit },
  );
  await approveToolCall(
    { toolName: "custom_tool", input: {} },
    { workspace, mode: "tui", ui: ui(["Deny"]).value, audit, assess: async () => { throw new DOMException("timed out", "TimeoutError"); } },
  );
  await approveToolCall(
    { toolName: "custom_tool", input: {} },
    { workspace, mode: "tui", ui: ui(["Deny"]).value, audit, assess: async () => { throw new Error("provider failed"); } },
  );

  assert.deepEqual(events.map(({ decisionSource, outcome, riskLevel }) => ({ decisionSource, outcome, riskLevel })), [
    { decisionSource: "ai-judge", outcome: "allowed", riskLevel: "low" },
    { decisionSource: "ai-judge", outcome: "allowed", riskLevel: "medium" },
    { decisionSource: "ai-judge", outcome: "approval-required", riskLevel: "high" },
    { decisionSource: "human", outcome: "allowed", riskLevel: "high" },
    { decisionSource: "ai-judge", outcome: "approval-required", riskLevel: "high" },
    { decisionSource: "human", outcome: "denied", riskLevel: "high" },
    { decisionSource: "hard-guard", outcome: "approval-required", riskLevel: "high" },
    { decisionSource: "human", outcome: "denied", riskLevel: "high" },
    { decisionSource: "ai-judge", outcome: "timeout", riskLevel: "high" },
    { decisionSource: "human", outcome: "denied", riskLevel: "high" },
    { decisionSource: "ai-judge", outcome: "judge-error", riskLevel: "high" },
    { decisionSource: "human", outcome: "denied", riskLevel: "high" },
  ]);
  assert.equal(events[0].workingDirectory, await realpath(workspace));
  assert.equal(events[0].modelIdentifier, "provider/model");
  assert.equal(events[6].modelIdentifier, "unavailable");
  assert.equal(typeof events[0].judgeLatencyMs, "number");
  assert.deepEqual(events[0].arguments, { password: "hidden", value: "low" });
});

test("an audit failure never changes the Tool Call result", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-audit-failure-"));
  const failedUi = ui();
  const result = await approveToolCall(
    { toolName: "custom_tool", input: {} },
    {
      workspace,
      mode: "tui",
      ui: failedUi.value,
      assess: async () => ({ riskLevel: "low", operation: "Read state", riskExplanation: "No state changes." }),
      audit: async () => { throw new Error("disk full"); },
    },
  );
  assert.deepEqual(result, {});
  assert.match(failedUi.notifications[0], /audit/i);
});
