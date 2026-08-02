/**
 * Command segmentation + rule matching + destructive-path analysis.
 */

import {
	bashRules,
	loadConfig,
	getProtectedCategories,
	isAppBundlePath,
	type BashRule,
	type Severity,
	type ProtectedCategory,
} from "./rules.ts";
import { extractDestructiveTargets, targetExists, type ExtractedTarget } from "./paths.ts";
import { resolve, isAbsolute } from "node:path";
import { homedir } from "node:os";

export interface RuleHit {
	name: string;
	severity: Severity;
	/** Plain-language description of what the operation does. */
	description?: string;
	/** Matched target path (if any). */
	path?: string;
}

export interface BashAnalysis {
	dangerous: boolean;
	hits: RuleHit[];
}

/**
 * Split a full bash command string into segments by &&, ||, ;, and pipe.
 * This is a coarse split — it does not parse quotes/escapes. Conservative:
 * over-segmenting is fine because we match per segment.
 */
function splitSegments(command: string): string[] {
	return command
		.split(/\s*(?:&&|\|\||;|\|)\s*/)
		.map((s) => s.trim())
		.filter(Boolean);
}

/** Analyze a bash command for dangerous segments and protected-path targets. */
export function analyzeBash(command: string, cwd: string = process.cwd()): BashAnalysis {
	const config = loadConfig();
	const disabled = new Set(config.disableRules);

	const segmentTexts = splitSegments(command);
	const hits: RuleHit[] = [];

	const testAgainst = (rules: BashRule[], text: string) => {
		for (const rule of rules) {
			if (disabled.has(rule.name)) continue;
			if (rule.pattern.test(text)) {
				hits.push({ name: rule.name, severity: rule.severity });
			}
		}
	};

	// Per-segment matching.
	for (const seg of segmentTexts) testAgainst(bashRules, seg);
	// Full-command matching for rules that span segments (e.g. curl|sh).
	testAgainst(bashRules, command);

	// Path-based destructive analysis.
	const cats = getProtectedCategories(config);
	const targets = extractDestructiveTargets(command, cwd);
	for (const t of targets) {
		for (const h of evaluateTarget(t, cats)) hits.push(h);
	}

	// Deduplicate by name + path.
	const seen = new Set<string>();
	const unique = hits.filter((h) => {
		const key = `${h.name}|${h.path ?? ""}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});

	return {
		dangerous: unique.length > 0,
		hits: unique,
	};
}

type PrefixMatch = "exact" | "subpath";

function matchPrefix(path: string, prefixes: string[]): PrefixMatch | null {
	for (const p of prefixes) {
		if (path === p) return "exact";
		const base = p.endsWith("/") ? p : p + "/";
		if (path.startsWith(base)) return "subpath";
	}
	return null;
}

function describeDelete(t: ExtractedTarget, cat: ProtectedCategory): string {
	if (t.recursive) return `递归删除${cat.label}`;
	return `删除${cat.label}中的文件`;
}

/** Evaluate one extracted target against all protected categories. */
function evaluateTarget(t: ExtractedTarget, cats: ProtectedCategory[]): RuleHit[] {
	const hits: RuleHit[] = [];
	const appBundle = isAppBundlePath(t.path);

	for (const cat of cats) {
		const m = matchPrefix(t.path, cat.prefixes);
		if (!m) continue;
		const exact = m === "exact";
		if (cat.exactOnly && !exact) continue;
		let severity: Severity | null = null;
		let desc = "";

		if (cat.tier === "always") {
			// Tier 1: any destructive/overwrite/relocate to sensitive locations → block.
			if (t.op === "relocate" && t.role === "source") {
				if (!exact) continue; // per-file mv-away: skip
				severity = "block";
				desc = `搬移整个${cat.label}`;
			} else if (t.op === "overwrite") {
				severity = "block";
				desc = t.append ? `追加写入${cat.label}` : `覆盖${cat.label}`;
			} else {
				// delete
				severity = "block";
				desc = exact ? `删除整个${cat.label}` : describeDelete(t, cat);
			}
		} else {
			// Tier 2: destructive-only.
			if (t.op === "relocate" && t.role === "source") {
				if (!exact) continue; // per-file mv-away: skip
				severity = "block";
				desc = `搬移整个${cat.label}`;
			} else if (t.op === "overwrite") {
				if (t.append) continue; // `>>` to user/app file is benign
				if (!targetExists(t)) continue; // creating a new file: skip
				severity = cat.severity;
				desc = `覆盖${cat.label}中的文件`;
			} else {
				// delete
				if (exact || t.recursive || cat.severity === "block" || appBundle) {
					severity = "block";
					desc = exact
						? `删除整个${cat.label}`
						: t.recursive
							? `递归删除${cat.label}`
							: appBundle
								? `删除应用程序 (.app)`
								: `删除${cat.label}`;
				} else {
					severity = cat.severity;
					desc = `删除${cat.label}中的文件`;
				}
			}
		}

		if (severity) {
			hits.push({
				name: `${cat.name} (${t.via})`,
				severity,
				description: desc,
				path: t.path,
			});
		}
	}

	// App-bundle escalation: any deletion of a .app becomes block.
	if (appBundle) {
		for (const h of hits) {
			if (h.severity === "warn" && /删除/.test(h.description ?? "")) {
				h.severity = "block";
				h.description = "删除应用程序 (.app)";
			}
		}
	}

	return hits;
}

const pathCategories: ProtectedCategory[] = getProtectedCategories(loadConfig()).filter((c) => c.tier === "always");

/** Expand a leading ~ to the home directory. */
function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/") || p.startsWith("~\\")) {
		const h = homedir();
		return h.endsWith("/") ? h + p.slice(2) : h + "/" + p.slice(2);
	}
	return p;
}

/** Analyze a write/edit path. Returns hits if the resolved path is protected (Tier 1). */
export function analyzePath(rawPath: string, cwd: string = process.cwd()): RuleHit[] {
	const expanded = expandHome(rawPath);
	const resolved = isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);

	const hits: RuleHit[] = [];
	for (const rule of pathCategories) {
		for (const prefix of rule.prefixes) {
			const p = isAbsolute(prefix) ? prefix : resolve(cwd, prefix);
			const exact = resolved === p;
			const base = p.endsWith("/") ? p : p + "/";
			const sub = !exact && resolved.startsWith(base);
			if (exact || sub) {
				hits.push({
					name: `${rule.name}: ${prefix}`,
					severity: rule.severity,
					description: `写入${rule.label}`,
					path: resolved,
				});
				break; // one hit per rule
			}
		}
	}
	return hits;
}

