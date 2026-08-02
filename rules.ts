/**
 * Dangerous operation rules.
 *
 * Each bash rule has a regex tested against individual command segments
 * (split by &&, ||, ;, |) and a severity used to pick the default
 * confirmation choice.
 *
 * Path protection rules apply to write/edit tools AND to destructive bash
 * commands (rm, mv, cp, truncate, redirects, find -delete). See paths.ts
 * and analyze.ts for the bash path-extraction layer.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

export type Severity = "block" | "warn";

export interface BashRule {
	name: string;
	pattern: RegExp;
	severity: Severity;
}

/** Tier 1 = any operation (write/edit/overwrite/delete) is blocked. */
export type PathTier = "always" | "destructive";

export interface PathRule {
	name: string;
	/** Resolved absolute path prefixes to protect. */
	prefixes: string[];
	severity: Severity;
	tier: PathTier;
	/** Human label, used in confirmation messages. */
	label: string;
	/** If true, only an exact match triggers (not subpaths). */
	exactOnly?: boolean;
}

/** Alias kept for clarity in the destructive-path layer. */
export type ProtectedCategory = PathRule;

export interface AppConfig {
	/** Extra Tier-1 prefixes (any operation blocked). */
	extraAlwaysProtected: string[];
	/** Extra Tier-2 prefixes (only delete/overwrite confirmed). */
	extraDestructiveProtected: string[];
	/** Treat the entire home directory as Tier-2 (any home file delete confirmed). */
	protectAllHome: boolean;
	/** Base severity for single user-data file deletion. */
	userDataSeverity: Severity;
	/** Base severity for application file deletion. */
	appSeverity: Severity;
	/** Rule names to disable (escape hatch). */
	disableRules: string[];
}

/**
 * macOS system roots that, when targeted by destructive commands, are
 * considered high-risk (irreversible damage).
 */
export const SYSTEM_ROOTS = [
	"/System",
	"/Library",
	"/usr",
	"/bin",
	"/sbin",
	"/etc",
	"/private/etc",
	"/private/var",
	"/private",
];

/**
 * Home-relative sensitive roots.
 */
const HOME_SENSITIVE = [
	"~/.ssh",
	"~/.gnupg",
	"~/Library/Keychains",
];

/**
 * Shell startup files that, if overwritten, can be used to inject code.
 */
const SHELL_RC_FILES = [
	"~/.zshrc",
	"~/.zprofile",
	"~/.zshenv",
	"~/.bashrc",
	"~/.bash_profile",
	"~/.profile",
];

/**
 * Credential files.
 */
const CREDENTIAL_FILES = [
	"~/.npmrc",
	"~/.pypirc",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/hosts",
];

/**
 * Standard macOS user data directories (Tier-2: only delete/overwrite confirmed).
 */
const USER_DATA_DIRS = [
	"~/Desktop",
	"~/Documents",
	"~/Downloads",
	"~/Pictures",
	"~/Music",
	"~/Movies",
	"~/Library",
];

/**
 * Application locations (Tier-2). Deleting these removes installed apps
 * or breaks package managers (Homebrew, etc.).
 */
const APP_DIRS = [
	"/Applications",
	"~/Applications",
	"/Library/Application Support",
	"~/Library/Application Support",
	"/usr/local",
	"/opt",
];

/** Bash command rules. Order matters only for display. */
export const bashRules: BashRule[] = [
	// --- Deletion of system roots (highest risk) ---
	{
		name: "rm recursive on system root",
		pattern: new RegExp(
			`\\brm\\b[^;|&]*(-[a-zA-Z]*[rR][a-zA-Z-]*|--recursive)[^;|&]*(${SYSTEM_ROOTS.filter(
				(r) => r !== "/",
			)
				.map(escapeRegex)
				.join("|")}|/(\\s|$))`,
			"i",
		),
		severity: "block",
	},
	{
		name: "rm force recursive anywhere",
		pattern: /\brm\b[^;|&]*(-[a-zA-Z]*[rR][a-zA-Z-]*[fF][a-zA-Z-]*|--recursive[^;|&]*--force|-[a-zA-Z]*[fF][a-zA-Z-]*[rR][a-zA-Z-]*)[^;|&]*(-[a-zA-Z]*[rRfF]|--recursive|--force)*/i,
		severity: "block",
	},
	{
		name: "find -delete",
		pattern: /\bfind\b[^;|&]*-delete\b/i,
		severity: "block",
	},
	{
		name: "find -exec rm",
		pattern: /\bfind\b[^;|&]*-exec\s+rm\b/i,
		severity: "block",
	},
	{
		name: "rmdir on system root",
		pattern: new RegExp(
			`\\brmdir\\b[^;|&]*(${SYSTEM_ROOTS.filter((r) => r !== "/")
				.map(escapeRegex)
				.join("|")}|/(\\s|$))`,
			"i",
		),
		severity: "block",
	},

	// --- Privilege / system ---
	{
		name: "sudo",
		pattern: /\bsudo\b/i,
		severity: "block",
	},
	{
		name: "chmod/chown 777",
		pattern: /\b(chmod|chown)\b[^;|&]*777\b/i,
		severity: "block",
	},
	{
		name: "chmod/chown on system root",
		pattern: new RegExp(
			`\\b(chmod|chown)\\b[^;|&]*(${SYSTEM_ROOTS.filter((r) => r !== "/")
				.map(escapeRegex)
				.join("|")})`,
			"i",
		),
		severity: "block",
	},

	// --- Disk / system imaging (irreversible) ---
	{
		name: "diskutil destructive",
		pattern: /\bdiskutil\b[^;|&]*(eraseDisk|partitionDisk|reformat|eraseVolume|mergePartitions|splitPartitions)/i,
		severity: "block",
	},
	{
		name: "dd",
		pattern: /\bdd\b[^;|&]*\b(if|of)=/i,
		severity: "block",
	},
	{
		name: "mkfs / fdisk / gpt",
		pattern: /\b(mkfs|fdisk|gpt)\b/i,
		severity: "block",
	},
	{
		name: "csrutil",
		pattern: /\bcsrutil\b/i,
		severity: "block",
	},
	{
		name: "nvram",
		pattern: /\bnvram\b/i,
		severity: "block",
	},

	// --- System modification ---
	{
		name: "write to /etc (hosts, sudoers, fstab)",
		pattern: /(^|[\s;&|])(tee|cp|mv|cat|echo|printf)\b[^;|&]*\b(\/etc\/(hosts|sudoers|fstab|sudoers\.d)|\/private\/etc)/i,
		severity: "block",
	},
	{
		name: "softwareupdate / installer (pkg)",
		pattern: /\b(softwareupdate|installer)\b/i,
		severity: "block",
	},
	{
		name: "launchctl system level",
		pattern: /\blaunchctl\b[^;|&]*(load|unload|bootout|bootstrap)\b/i,
		severity: "block",
	},
	{
		name: "tmutil destructive",
		pattern: /\btmutil\b[^;|&]*(delete|disable|remove)/i,
		severity: "block",
	},
	{
		name: "apfs",
		pattern: /\bapfs\b/i,
		severity: "block",
	},

	// --- Remote execution ---
	{
		name: "curl/wget piped to shell",
		pattern: /\b(curl|wget)\b[^;|&|]*\|[^;|&]*\b(sh|bash|zsh|python|perl|ruby)\b/i,
		severity: "block",
	},

	// --- Process kill (system critical) ---
	{
		name: "kill kernel_task / launchd",
		pattern: /\b(kill|killall)\b[^;|&]*(launchd|kernel_task)/i,
		severity: "block",
	},
];

function expand(p: string, home: string): string {
	if (p === "~") return home;
	if (p.startsWith("~/") || p.startsWith("~\\")) return join(home, p.slice(2));
	return p;
}

function join(base: string, rest: string): string {
	if (base.endsWith("/")) return base + rest;
	return base + "/" + rest;
}

let cachedConfig: AppConfig | null = null;

const CONFIG_PATH = join(homedir(), ".pi/agent/extensions/dangerous-ops/config.json");

/** Load optional config from disk, merged with defaults. Cached. */
export function loadConfig(): AppConfig {
	if (cachedConfig) return cachedConfig;
	const defaults: AppConfig = {
		extraAlwaysProtected: [],
		extraDestructiveProtected: [],
		protectAllHome: false,
		userDataSeverity: "warn",
		appSeverity: "block",
		disableRules: [],
	};
	try {
		const raw = readFileSync(CONFIG_PATH, "utf8");
		const parsed = JSON.parse(raw);
		cachedConfig = {
			...defaults,
			...parsed,
			extraAlwaysProtected: Array.isArray(parsed.extraAlwaysProtected) ? parsed.extraAlwaysProtected : [],
			extraDestructiveProtected: Array.isArray(parsed.extraDestructiveProtected) ? parsed.extraDestructiveProtected : [],
			disableRules: Array.isArray(parsed.disableRules) ? parsed.disableRules : [],
		};
	} catch {
		cachedConfig = defaults;
	}
	return cachedConfig;
}

/** Test environment override hook (used by tests). */
export function _resetConfigCache(): void {
	cachedConfig = null;
}

/**
 * Build the full list of protected path categories (Tier 1 + Tier 2),
 * expanding ~ against the home dir and applying config extras.
 */
export function getProtectedCategories(config: AppConfig): ProtectedCategory[] {
	const home = homedir();
	const cats: ProtectedCategory[] = [
		{
			name: "system directory",
			prefixes: SYSTEM_ROOTS.slice(),
			severity: "block",
			tier: "always",
			label: "系统目录",
		},
		{
			name: "sensitive home directory",
			prefixes: HOME_SENSITIVE.map((p) => expand(p, home)),
			severity: "block",
			tier: "always",
			label: "敏感目录",
		},
		{
			name: "shell startup file",
			prefixes: SHELL_RC_FILES.map((p) => expand(p, home)),
			severity: "block",
			tier: "always",
			label: "Shell 配置文件",
		},
		{
			name: "credential file",
			prefixes: CREDENTIAL_FILES.map((p) => expand(p, home)),
			severity: "block",
			tier: "always",
			label: "凭证文件",
		},
		{
			name: "user data",
			prefixes: USER_DATA_DIRS.map((p) => expand(p, home)),
			severity: config.userDataSeverity,
			tier: "destructive",
			label: "用户文件",
		},
		{
			name: "home directory",
			prefixes: [home],
			severity: "block",
			tier: "destructive",
			label: "家目录",
			exactOnly: true,
		},
		{
			name: "application",
			prefixes: APP_DIRS.map((p) => expand(p, home)),
			severity: config.appSeverity,
			tier: "destructive",
			label: "应用程序",
		},
	];

	for (const p of config.extraAlwaysProtected) {
		cats.push({ name: "extra protected", prefixes: [expand(p, home)], severity: "block", tier: "always", label: "受保护路径" });
	}
	for (const p of config.extraDestructiveProtected) {
		cats.push({ name: "extra destructive-protected", prefixes: [expand(p, home)], severity: "warn", tier: "destructive", label: "受保护路径" });
	}
	if (config.protectAllHome) {
		cats.push({ name: "home (all)", prefixes: [home], severity: config.userDataSeverity, tier: "destructive", label: "家目录文件" });
	}

	// Filter disabled categories.
	return cats.filter((c) => !config.disableRules.includes(c.name));
}

/** True if any path component ends with `.app` (an application bundle). */
export function isAppBundlePath(path: string): boolean {
	return /(^|\/)[^/]+\.app(\/|$)/.test(path);
}

/** Build Tier-1 path rules for the write/edit tools (legacy helper). */
export function buildPathRules(home: string): PathRule[] {
	return getProtectedCategories(loadConfig())
		.filter((c) => c.tier === "always")
		.map((c) => ({ ...c, prefixes: c.prefixes.slice() }));
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
