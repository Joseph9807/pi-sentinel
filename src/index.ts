import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { approveToolCall } from "./pipeline.ts";

export default function sentinel(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event, ctx) => {
    const result = await approveToolCall(
      { toolName: event.toolName, input: event.input },
      { workspace: ctx.cwd, mode: ctx.mode, ui: ctx.ui },
    );
    return result.block ? result : undefined;
  });
}
