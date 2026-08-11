import { getAgentDir, type ExtensionAPI, type ExtensionContext, type ToolInfo } from "@earendil-works/pi-coding-agent";
import { writeAuditEvent } from "./audit.ts";
import { assessWithPi, type RiskAssessment } from "./judge.ts";
import { approveToolCall, type ApprovalQueue } from "./pipeline.ts";
import { inspectRemoteScript } from "./remote-script.ts";

export default function sentinel(pi: ExtensionAPI): void {
  const decisionCache = new Map<string, Promise<RiskAssessment>>();
  const approvalQueue: ApprovalQueue = { tail: Promise.resolve() };
  pi.on("session_start", () => { decisionCache.clear(); });
  pi.on("tool_call", async (event, ctx) => {
    const tool = pi.getAllTools().find((candidate) => candidate.name === event.toolName);
    const result = await approveToolCall(
      { toolName: event.toolName, input: event.input },
      {
        workspace: ctx.cwd,
        mode: ctx.mode,
        ui: ctx.ui,
        signal: ctx.signal,
        tool: toolContext(tool),
        userRequest: latestUserRequest(ctx),
        assess: (input, signal) => assessWithPi(input, signal, ctx),
        audit: (auditEvent) => writeAuditEvent(auditEvent, getAgentDir()),
        modelIdentifier: ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined,
        decisionCache,
        approvalQueue,
        inspectRemoteScript: (url, signal) => inspectRemoteScript(url, { signal }),
      },
    );
    return result.block ? result : undefined;
  });
}

function toolContext(tool: ToolInfo | undefined) {
  return {
    description: tool?.description ?? "No tool definition is available.",
    parameters: tool?.parameters ?? {},
  };
}

function latestUserRequest(ctx: ExtensionContext): string {
  const branch = ctx.sessionManager.getBranch();
  for (let index = branch.length - 1; index >= 0; index--) {
    const entry = branch[index];
    if (entry.type !== "message" || entry.message.role !== "user") continue;
    if (typeof entry.message.content === "string") return entry.message.content;
    return entry.message.content
      .filter((part): part is { type: "text"; text: string } => part.type === "text")
      .map((part) => part.text)
      .join("\n");
  }
  return "No user request is available.";
}
