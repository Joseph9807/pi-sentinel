/**
 * Approval dialog helpers.
 *
 * Presents a clear yes/no confirmation describing what the operation does,
 * the command/path involved, and the rules that triggered. The default
 * choice reflects severity: irreversible (block) defaults to "拒绝",
 * reversible-ish (warn) defaults to "允许执行".
 */

import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { RuleHit } from "./analyze.ts";

export interface ApprovalRequest {
	toolName: string;
	hits: RuleHit[];
	/** Short detail: command or path. */
	detail: string;
	/** Full command for bash; same as detail for write/edit. */
	full?: string;
}

export type ApprovalResult = "allow" | "block";

/**
 * Prompt the user. Returns "allow" or "block".
 * If there is no UI (print/json mode), returns "block".
 */
export async function requestApproval(
	ctx: ExtensionContext,
	req: ApprovalRequest,
): Promise<ApprovalResult> {
	if (!ctx.hasUI) {
		ctx.ui.notify(
			`Blocked dangerous ${req.toolName} operation (no UI for confirmation): ${req.hits[0]?.name}`,
			"warning",
		);
		return "block";
	}

	const anyBlock = req.hits.some((h) => h.severity === "block");
	const icon = anyBlock ? "⚠️" : "⚠";
	const title = `${icon} 即将执行有风险的操作，请确认`;

	const lines: string[] = [title, ""];

	// Plain-language description of what the operation does.
	const descs = req.hits.map((h) => h.description).filter((d): d is string => Boolean(d));
	if (descs.length > 0) {
		lines.push("操作说明:");
		for (const d of descs) lines.push(`  • ${d}`);
		lines.push("");
	}

	// Command (bash) or path (write/edit).
	if (req.toolName === "bash") {
		const cmd = req.full && req.full !== req.detail ? req.full : req.detail;
		lines.push(`命令: ${cmd}`);
	} else {
		lines.push(`路径: ${req.detail}`);
	}

	// Matched target paths.
	const paths = req.hits.map((h) => h.path).filter((p): p is string => Boolean(p));
	if (paths.length > 0) {
		lines.push("");
		lines.push("目标:");
		for (const p of paths) lines.push(`  • ${p}`);
	}

	// Matched rules.
	lines.push("");
	lines.push("命中规则:");
	for (const h of req.hits) lines.push(`  • [${h.severity}] ${h.name}`);

	const allow = "允许执行";
	const deny = "拒绝";
	const choices = anyBlock ? [deny, allow] : [allow, deny];

	const choice = await ctx.ui.select(lines.join("\n"), choices);
	if (choice === allow) return "allow";
	return "block";
}

/** Build the block reason returned to the LLM. */
export function blockReason(req: ApprovalRequest): string {
	const descs = req.hits.map((h) => h.description).filter(Boolean).join("; ");
	const names = req.hits.map((h) => h.name).join(", ");
	return `Blocked by dangerous-ops extension. ${descs ? descs + " | " : ""}Matched rules: ${names}. Re-run in interactive mode and approve, or use a safer alternative.`;
}
