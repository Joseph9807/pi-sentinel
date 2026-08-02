/**
 * Quote-aware tokenizer + destructive-command target extraction.
 *
 * The existing regex rules in rules.ts catch *patterns* (rm -rf, sudo, dd, …).
 * This module complements them by *extracting the actual file paths* targeted
 * by destructive commands (rm, mv, cp, truncate, tee, find -delete, shell
 * redirects) so they can be checked against the protected-path categories.
 *
 * The tokenizer is intentionally pragmatic: it respects single/double quotes
 * and backslash escapes, and recognises shell operators (&&, ||, ;, |, >, >>, <).
 * It is NOT a full POSIX shell parser.
 */

import { resolve, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { statSync } from "node:fs";

export type Op = "delete" | "overwrite" | "relocate";

export interface ExtractedTarget {
	/** Original argument as written. */
	raw: string;
	/** Resolved absolute path. For globs, the literal prefix before the first glob char. */
	path: string;
	role: "source" | "dest";
	recursive: boolean;
	force: boolean;
	/** `>>` (append) vs `>` (truncate). */
	append: boolean;
	op: Op;
	/** Originating command name (rm, mv, …). */
	via: string;
	isGlob: boolean;
}

type Tok = { t: "w"; v: string; q: boolean } | { t: "o"; v: string };

/** Tokenize a command string into words and operators, respecting quotes. */
function tokenize(input: string): Tok[] {
	const toks: Tok[] = [];
	let cur = "";
	let quote: '"' | "'" | null = null;
	let hadQuoted = false;
	let hadUnquoted = false;
	const flushWord = () => {
		if (cur !== "" || hadQuoted) {
			toks.push({ t: "w", v: cur, q: hadQuoted && !hadUnquoted });
		}
		cur = "";
		hadQuoted = false;
		hadUnquoted = false;
	};

	for (let i = 0; i < input.length; i++) {
		const c = input[i];
		if (quote) {
			if (c === quote) {
				quote = null;
				continue;
			}
			if (quote === '"' && c === "\\") {
				const n = input[i + 1];
				if (n !== undefined) cur += n;
				i++;
				continue;
			}
			cur += c;
			hadQuoted = true;
			continue;
		}
		if (c === '"' || c === "'") {
			quote = c;
			hadQuoted = true;
			continue;
		}
		if (c === "\\") {
			const n = input[i + 1];
			if (n !== undefined) cur += n;
			i++;
			hadUnquoted = true;
			continue;
		}
		if (/\s/.test(c)) {
			flushWord();
			continue;
		}
		// Operators.
		if (c === "&") {
			if (input[i + 1] === "&") {
				flushWord();
				toks.push({ t: "o", v: "&&" });
				i++;
			} else {
				flushWord();
				toks.push({ t: "o", v: "&" });
			}
			continue;
		}
		if (c === "|") {
			if (input[i + 1] === "|") {
				flushWord();
				toks.push({ t: "o", v: "||" });
				i++;
			} else {
				flushWord();
				toks.push({ t: "o", v: "|" });
			}
			continue;
		}
		if (c === ";") {
			flushWord();
			toks.push({ t: "o", v: ";" });
			continue;
		}
		if (c === ">") {
			if (input[i + 1] === ">") {
				flushWord();
				toks.push({ t: "o", v: ">>" });
				i++;
			} else {
				flushWord();
				toks.push({ t: "o", v: ">" });
			}
			continue;
		}
		if (c === "<") {
			flushWord();
			toks.push({ t: "o", v: "<" });
			continue;
		}
		cur += c;
		hadUnquoted = true;
	}
	flushWord();
	return toks;
}

const SEGMENT_OPS = new Set(["&&", "||", ";", "|", "&"]);

/** Split tokens into segments at command separators. */
function segments(toks: Tok[]): Tok[][] {
	const segs: Tok[][] = [[]];
	for (const tk of toks) {
		if (tk.t === "o" && SEGMENT_OPS.has(tk.v)) {
			segs.push([]);
		} else {
			segs[segs.length - 1].push(tk);
		}
	}
	return segs.filter((s) => s.length > 0);
}

function basename(p: string): string {
	const s = p.replace(/\\/g, "/");
	const i = s.lastIndexOf("/");
	return i >= 0 ? s.slice(i + 1) : s;
}

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/") || p.startsWith("~\\")) {
		const h = homedir();
		return h.endsWith("/") ? h + p.slice(2) : h + "/" + p.slice(2);
	}
	return p;
}

interface ParsedFlags {
	recursive: boolean;
	force: boolean;
	positional: { v: string; q: boolean }[];
}

function parseFlags(args: { v: string; q: boolean }[]): ParsedFlags {
	let recursive = false;
	let force = false;
	let end = false;
	const positional: { v: string; q: boolean }[] = [];
	for (const w of args) {
		if (end) {
			positional.push(w);
			continue;
		}
		if (w.v === "--") {
			end = true;
			continue;
		}
		if (!w.q && w.v.startsWith("-") && w.v.length > 1 && w.v !== "-") {
			if (w.v === "--recursive" || w.v === "-R" || w.v === "-r") recursive = true;
			if (w.v === "--force" || w.v === "-f") force = true;
			// Combined short flags like -rf, -fr, -rfv.
			if (/^-[^-]/.test(w.v)) {
				if (/[rR]/.test(w.v)) recursive = true;
				if (/f/.test(w.v)) force = true;
			}
			continue;
		}
		positional.push(w);
	}
	return { recursive, force, positional };
}

function resolveTarget(v: string, q: boolean, cwd: string, via: string): ExtractedTarget | null {
	const isGlob = !q && /[*?\[]/.test(v);
	let rawForResolve = v;
	if (isGlob) {
		const m = v.match(/^[^*?\[]*/);
		rawForResolve = m ? m[0] : v;
	}
	if (rawForResolve === "") return null;
	const expanded = expandHome(rawForResolve);
	const resolved = isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
	return {
		raw: v,
		path: resolved,
		role: "source",
		recursive: false,
		force: false,
		append: false,
		op: "delete",
		via,
		isGlob,
	};
}

/** Commands whose leading words to skip (env assignments, sudo, etc.). */
const LEAD_SKIPLIST = new Set(["sudo", "command", "env", "nohup", "exec", "time"]);

/** Process a single command segment, returning destructive targets. */
function processSegment(seg: Tok[], cwd: string): ExtractedTarget[] {
	const words = seg.filter((t): t is { t: "w"; v: string; q: boolean } => t.t === "w");
	if (words.length === 0) return [];

	let idx = 0;
	// Skip leading VAR=value assignments.
	while (idx < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[idx].v)) idx++;
	// Skip sudo / command / env / …
	if (idx < words.length && LEAD_SKIPLIST.has(basename(words[idx].v).replace(/^\\/, ""))) idx++;
	while (idx < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[idx].v)) idx++;
	if (idx >= words.length) return [];

	const cmd = basename(words[idx].v).replace(/^\\/, "");
	idx++;
	const args = words.slice(idx);
	const targets: ExtractedTarget[] = [];

	switch (cmd) {
		case "rm": {
			const { recursive, force, positional } = parseFlags(args);
			for (const w of positional) {
				const tg = resolveTarget(w.v, w.q, cwd, cmd);
				if (tg) {
					tg.recursive = recursive;
					tg.force = force;
					tg.op = "delete";
					targets.push(tg);
				}
			}
			break;
		}
		case "rmdir": {
			const { positional } = parseFlags(args);
			for (const w of positional) {
				const tg = resolveTarget(w.v, w.q, cwd, cmd);
				if (tg) {
					tg.op = "delete";
					targets.push(tg);
				}
			}
			break;
		}
		case "truncate": {
			const { positional } = parseFlags(args);
			for (const w of positional) {
				const tg = resolveTarget(w.v, w.q, cwd, cmd);
				if (tg) {
					tg.op = "overwrite";
					tg.role = "dest";
					targets.push(tg);
				}
			}
			break;
		}
		case "mv":
		case "cp": {
			const { recursive, force, positional } = parseFlags(args);
			if (positional.length >= 2) {
				const dest = positional[positional.length - 1];
				const sources = positional.slice(0, -1);
				for (const w of sources) {
					const tg = resolveTarget(w.v, w.q, cwd, cmd);
					if (tg) {
						tg.op = "relocate";
						tg.role = "source";
						tg.recursive = recursive;
						tg.force = force;
						targets.push(tg);
					}
				}
				const dt = resolveTarget(dest.v, dest.q, cwd, cmd);
				if (dt) {
					dt.op = "overwrite";
					dt.role = "dest";
					dt.recursive = recursive;
					dt.force = force;
					targets.push(dt);
				}
			}
			break;
		}
		case "tee": {
			const append = args.some((a) => a.v === "-a");
			const { positional } = parseFlags(args);
			for (const w of positional) {
				const tg = resolveTarget(w.v, w.q, cwd, cmd);
				if (tg) {
					tg.op = "overwrite";
					tg.role = "dest";
					tg.append = append;
					targets.push(tg);
				}
			}
			break;
		}
		case "find": {
			const hasDelete = args.some((a) => a.v === "-delete");
			const hasExecRm = args.some((a) => a.v === "-exec" || a.v === "exec") &&
				args.some((a) => basename(a.v) === "rm");
			if (hasDelete || hasExecRm) {
				// First non-flag word is the search root.
				for (const a of args) {
					if (a.v === "--") continue;
					if (!a.q && a.v.startsWith("-") && a.v.length > 1) continue;
					const tg = resolveTarget(a.v, a.q, cwd, cmd);
					if (tg) {
						tg.op = "delete";
						tg.recursive = true;
						targets.push(tg);
					}
					break;
				}
			}
			break;
		}
		default:
			break;
	}

	// Shell redirects: `> file` / `>> file` / `2> file`.
	for (let i = 0; i < seg.length - 1; i++) {
		const cur = seg[i];
		const next = seg[i + 1];
		if (cur.t === "o" && (cur.v === ">" || cur.v === ">>")) {
			if (next.t === "w") {
				const tg = resolveTarget(next.v, next.q, cwd, `${cmd} (redirect)`);
				if (tg) {
					tg.op = "overwrite";
					tg.role = "dest";
					tg.append = cur.v === ">>";
					targets.push(tg);
				}
			}
		}
	}

	return targets;
}

/** Extract all destructive targets from a full bash command string. */
export function extractDestructiveTargets(command: string, cwd: string): ExtractedTarget[] {
	const toks = tokenize(command);
	const segs = segments(toks);
	const out: ExtractedTarget[] = [];
	for (const s of segs) out.push(...processSegment(s, cwd));
	return out;
}

/** Whether the target path currently exists on disk (for overwrite detection). */
export function targetExists(t: ExtractedTarget): boolean {
	try {
		statSync(t.path);
		return true;
	} catch {
		return false;
	}
}
