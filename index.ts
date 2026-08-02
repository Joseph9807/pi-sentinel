/**
 * Dangerous Operations Approval Extension
 *
 * Intercepts bash / write / edit tool calls that may cause irreversible
 * damage to macOS or mess up the filesystem, and asks the user to approve
 * before execution.
 *
 * Non-interactive modes (print/json) block by default.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { analyzeBash, analyzePath } from "./analyze.ts";
import { requestApproval, blockReason, type ApprovalRequest } from "./approve.ts";

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async (_event, ctx) => {
		ctx.ui.notify("dangerous-ops: approval gate active", "info");
	});

	pi.on("tool_call", async (event, ctx) => {
		const toolName = event.toolName;

		let req: ApprovalRequest | null = null;

		if (toolName === "bash") {
			const command = (event.input.command as string | undefined) ?? "";
			const analysis = analyzeBash(command, ctx.cwd);
			if (analysis.dangerous) {
				req = {
					toolName,
					hits: analysis.hits,
					detail: truncate(command, 200),
					full: command,
				};
			}
		} else if (toolName === "write" || toolName === "edit") {
			const rawPath = (event.input.path as string | undefined) ?? "";
			const hits = analyzePath(rawPath, ctx.cwd);
			if (hits.length > 0) {
				req = {
					toolName,
					hits,
					detail: rawPath,
				};
			}
		}

		if (!req) return undefined;

		const result = await requestApproval(ctx, req);
		if (result === "block") {
			return { block: true, reason: blockReason(req) };
		}
		return undefined;
	});
}

function truncate(s: string, n: number): string {
	if (s.length <= n) return s;
	return s.slice(0, n) + "…";
}
