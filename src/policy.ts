import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

export interface ToolCall {
  toolName: string;
  input: Record<string, unknown>;
}

export interface PolicyDecision {
  route: "safe-bypass" | "candidate" | "hard-guard";
  operation: string;
  riskExplanation: string;
  remoteScript?: { url: string } | { inspectionUnavailable: string };
}

const READ_ONLY_TOOLS = new Set(["read", "grep", "find", "ls"]);
const READ_ONLY_COMMANDS = new Set(["pwd", "ls", "cat", "head", "tail", "wc", "stat", "file", "which", "grep"]);
const READ_ONLY_GIT = new Set(["status", "diff", "log", "show", "rev-parse"]);
const SCRIPT_INTERPRETERS = new Set(["sh", "bash", "dash", "ash", "ksh", "zsh", "csh", "tcsh", "fish", "pwsh", "python", "perl", "ruby"]);
const SYSTEM_ROOTS = new Set([
  "/",
  "/System",
  "/Library",
  "/usr",
  "/bin",
  "/sbin",
  "/etc",
  "/var",
  "/private",
  "/private/etc",
  "/private/var",
]);

export async function classifyToolCall(call: ToolCall, workspace: string): Promise<PolicyDecision> {
  const canonicalWorkspace = await canonicalPath(workspace);

  if (READ_ONLY_TOOLS.has(call.toolName)) {
    return safe(`Read data with ${call.toolName}`);
  }

  if (call.toolName === "bash") {
    const command = typeof call.input.command === "string" ? call.input.command : "";
    const guard = await matchHardGuard(command, canonicalWorkspace);
    if (guard) return guard;
    if (isSafeShellCommand(command)) return safe(`Run read-only shell command: ${command}`);
    return candidate(`Run shell command: ${command}`, "The command is not proven read-only.");
  }

  if (call.toolName === "write" || call.toolName === "edit") {
    const path = typeof call.input.path === "string" ? call.input.path : "";
    if (path && (await isWorkspaceWrite(path, canonicalWorkspace))) {
      return safe(`${call.toolName === "write" ? "Write" : "Edit"} ${path}`);
    }
    return candidate(
      `${call.toolName === "write" ? "Write" : "Edit"} ${path || "an unspecified path"}`,
      "The target is outside the Workspace, in Git metadata, or cannot be proven contained.",
    );
  }

  return candidate(`Run tool ${call.toolName}`, "Unknown tools are not trusted automatically.");
}

export function isSafeShellCommand(command: string): boolean {
  const tokens = tokenize(command, false);
  if (!tokens || tokens.some((token) => token.operator)) return false;
  const words = tokens.map((token) => token.value);
  if (words.length === 0 || command.includes("\n")) return false;

  const name = basename(words[0]);
  if (READ_ONLY_COMMANDS.has(name)) return !words.some((word) => /^--?(output|files0-from)(=|$)/.test(word));
  if (name !== "git" || !READ_ONLY_GIT.has(words[1])) return false;
  return !words.some((word) => /^--?(output|ext-diff|textconv)(=|$)/.test(word));
}

export async function isWorkspaceWrite(path: string, workspace: string): Promise<boolean> {
  const target = await canonicalPath(isAbsolute(path) ? path : resolve(workspace, path));
  const rel = relative(workspace, target);
  if (rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) return false;
  return !rel.split(sep).some((part) => part.toLowerCase() === ".git");
}

export async function canonicalPath(path: string): Promise<string> {
  let existing = resolve(path);
  const missing: string[] = [];

  while (true) {
    try {
      return resolve(await realpath(existing), ...missing.reverse());
    } catch {
      const parent = dirname(existing);
      if (parent === existing) return resolve(path);
      missing.push(basename(existing));
      existing = parent;
    }
  }
}

export async function matchHardGuard(command: string, workspace: string): Promise<PolicyDecision | undefined> {
  workspace = await canonicalPath(workspace);
  if (/\b(?:diskutil\s+(?:eraseDisk|partitionDisk|eraseVolume|reformat|mergePartitions|splitPartitions)\b|mkfs(?:\.\w+)?\b|fdisk\b|gpt\s+(?:destroy|remove)\b|dd\b[^\n;&|]*\bof=\/dev\/)/i.test(command)) {
    return hard("Erase or repartition a disk", "This can irreversibly destroy disk data.");
  }
  const tokens = tokenize(command, true);
  if (!tokens) {
    const remoteScript = detectRemoteScriptExecution(command, []);
    return remoteScript
      ? { ...hard("Download and execute a remote script", "Unreviewed remote code would run on this machine."), remoteScript }
      : undefined;
  }
  if (isDestructiveGit(tokens)) {
    return hard("Discard Git working data", "This can permanently discard uncommitted work.");
  }
  const remoteScript = detectRemoteScriptExecution(command, tokens);
  if (remoteScript) {
    return { ...hard("Download and execute a remote script", "Unreviewed remote code would run on this machine."), remoteScript };
  }
  const home = await canonicalPath(homedir());
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].operator || !["rm", "rmdir"].includes(basename(tokens[i].value))) continue;
    for (const token of tokens.slice(i + 1)) {
      if (token.operator) break;
      const rawTarget = token.value;
      if (rawTarget.startsWith("-")) continue;
      const lexicalTarget = resolve(workspace, expandProtectedRoot(rawTarget, workspace));
      const target = await canonicalPath(lexicalTarget);
      if (SYSTEM_ROOTS.has(lexicalTarget) || target === home || target === workspace) {
        return hard(`Delete protected root ${target}`, "Deleting this root can cause catastrophic data loss.");
      }
      if (target.split(sep).some((part) => part.toLowerCase() === ".git")) {
        return hard(`Delete Git metadata at ${target}`, "Deleting Git metadata can destroy repository history and state.");
      }
    }
  }
  return undefined;
}

interface ShellToken {
  value: string;
  operator: boolean;
}

function tokenize(command: string, allowDollar: boolean): ShellToken[] | undefined {
  const tokens: ShellToken[] = [];
  let word = "";
  let quote: "'" | '"' | undefined;
  const flush = () => {
    if (word) tokens.push({ value: word, operator: false });
    word = "";
  };

  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    if (quote) {
      if (char === quote) quote = undefined;
      else if (char === "\\" && quote === '"' && command[i + 1]) word += command[++i];
      else if (quote === '"' && (char === "`" || (char === "$" && !allowDollar))) return undefined;
      else word += char;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
    } else if (/\s/.test(char)) {
      flush();
    } else if (";&|<>".includes(char)) {
      flush();
      let operator = char;
      if (command[i + 1] === char) operator += command[++i];
      tokens.push({ value: operator, operator: true });
    } else if (char === "`" || (char === "$" && !allowDollar) || char === "\\") {
      return undefined;
    } else {
      word += char;
    }
  }
  if (quote) return undefined;
  flush();
  return tokens;
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  return path.startsWith("~/") ? resolve(homedir(), path.slice(2)) : path;
}

function expandProtectedRoot(path: string, workspace: string): string {
  const root = path.endsWith("/") ? path.slice(0, -1) : path;
  if (root === "$HOME" || root === "${HOME}") return homedir();
  if (root === "$PWD" || root === "${PWD}") return workspace;
  return expandHome(path);
}

function isDestructiveGit(tokens: ShellToken[]): boolean {
  for (const segment of shellSegments(tokens)) {
    let index = segment.findIndex((word) => basename(word) === "git");
    if (index < 0) continue;
    index++;
    while (index < segment.length && segment[index].startsWith("-")) {
      const option = segment[index++];
      if (["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"].includes(option)) index++;
    }
    const subcommand = segment[index++];
    const args = segment.slice(index);
    if (subcommand === "reset" && args.some((arg) => ["--hard", "--merge"].includes(arg))) return true;
    if (subcommand === "clean" && args.some((arg) => arg === "--force" || /^-[^-]*f/i.test(arg))) return true;
    if (subcommand === "checkout" && args.some((arg) => ["--", "--force", "-f", "."].includes(arg))) return true;
    if (subcommand === "switch" && args.some((arg) => ["--discard-changes", "--force", "-f"].includes(arg))) return true;
    if (subcommand === "restore" && args.some((arg) => !arg.startsWith("-") || arg === "--worktree")) return true;
  }
  return false;
}

function detectRemoteScriptExecution(command: string, tokens: ShellToken[]): PolicyDecision["remoteScript"] | undefined {
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value !== "|") continue;
    const left = segmentBefore(tokens, i);
    const right = segmentAfter(tokens, i);
    const downloader = left.findIndex((word) => ["curl", "wget"].includes(basename(word)));
    if (downloader < 0) continue;
    const prefix = left.slice(0, downloader);
    const interpreter = right.findIndex((word) => SCRIPT_INTERPRETERS.has(basename(word)));
    if (interpreter < 0) continue;
    const directDownloader = prefix.every((word) => ["sudo", "env", "command"].includes(basename(word)) || /^[A-Za-z_]\w*=/.test(word));
    const directInterpreter = right.slice(0, interpreter).every((word) => ["sudo", "env"].includes(basename(word)) || /^[A-Za-z_]\w*=/.test(word));
    if (!directDownloader || !directInterpreter) {
      return { inspectionUnavailable: "Inspection requires supported direct curl/wget-to-shell syntax with one literal HTTP(S) URL." };
    }
    const urls = left.slice(downloader + 1).filter((word) => /^https?:\/\//i.test(word) && !/[$`]/.test(word));
    if (urls.length === 1) return { url: urls[0] };
    return { inspectionUnavailable: "Inspection requires one direct literal HTTP(S) URL." };
  }
  if (tokens.length === 0 && /\b(?:curl|wget)\b[\s\S]*\|\s*(?:(?:sudo|env)\s+)*(?:\S*\/)?(?:sh|bash|dash|ash|ksh|zsh|csh|tcsh|fish|pwsh|python|perl|ruby)\b/i.test(command)) {
    return { inspectionUnavailable: "Inspection requires supported direct curl/wget-to-shell syntax with one literal HTTP(S) URL." };
  }
  return undefined;
}

function shellSegments(tokens: ShellToken[]): string[][] {
  const segments: string[][] = [[]];
  for (const token of tokens) {
    if (token.operator) segments.push([]);
    else segments.at(-1)?.push(token.value);
  }
  return segments;
}

function segmentBefore(tokens: ShellToken[], index: number): string[] {
  let start = 0;
  for (let i = index - 1; i >= 0; i--) {
    if (tokens[i].operator) {
      start = i + 1;
      break;
    }
  }
  return tokens.slice(start, index).map((token) => token.value);
}

function segmentAfter(tokens: ShellToken[], index: number): string[] {
  const end = tokens.findIndex((token, tokenIndex) => tokenIndex > index && token.operator);
  return tokens.slice(index + 1, end < 0 ? undefined : end).map((token) => token.value);
}

function safe(operation: string): PolicyDecision {
  return {
    route: "safe-bypass",
    operation,
    riskExplanation: "The operation is deterministically read-only or Workspace-contained.",
  };
}

function candidate(operation: string, riskExplanation: string): PolicyDecision {
  return { route: "candidate", operation, riskExplanation };
}

function hard(operation: string, riskExplanation: string): PolicyDecision {
  return { route: "hard-guard", operation, riskExplanation };
}
