import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
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
