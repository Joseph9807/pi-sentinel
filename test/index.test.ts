import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import sentinel from "../src/index.ts";

type Handler = (event: Record<string, unknown>, context: Record<string, unknown>) => unknown;

test("starting a replacement session clears cached assessments", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sentinel-session-"));
  const agentDirectory = await mkdtemp(join(tmpdir(), "sentinel-agent-"));
  const previousAgentDirectory = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDirectory;
  const handlers = new Map<string, Handler>();
  let assessments = 0;
  const pi = {
    on(event: string, handler: Handler) { handlers.set(event, handler); },
    getAllTools() { return [{ name: "custom_tool", description: "Run a custom operation", parameters: {} }]; },
  };
  const context = {
    cwd: workspace,
    mode: "tui",
    signal: undefined,
    ui: { async select() { return undefined; }, async input() { return undefined; }, notify() {} },
    sessionManager: { getBranch() { return []; } },
    model: { provider: "test", id: "model" },
    modelRegistry: {
      hasConfiguredAuth() { return true; },
      async complete() {
        assessments++;
        return {
          stopReason: "stop",
          content: [{ type: "text", text: '{"riskLevel":"low","operation":"Read state","riskExplanation":"No state changes."}' }],
        };
      },
    },
  };

  try {
    sentinel(pi as never);
    const toolCall = handlers.get("tool_call")!;
    const event = { type: "tool_call", toolCallId: "call", toolName: "custom_tool", input: { value: 1 } };
    await toolCall(event, context);
    await toolCall(event, context);
    assert.equal(assessments, 1);

    await handlers.get("session_start")!({ type: "session_start", reason: "resume" }, context);
    await toolCall(event, context);
    assert.equal(assessments, 2);
  } finally {
    if (previousAgentDirectory === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDirectory;
  }
});
