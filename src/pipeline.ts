import { canonicalPath, classifyToolCall, type PolicyDecision, type ToolCall } from "./policy.ts";
import { type JudgeInput, type RiskAssessment, validateRiskAssessment } from "./judge.ts";
import type { AuditEvent } from "./audit.ts";

export type { RiskAssessment, RiskLevel } from "./judge.ts";

export interface ApprovalUI {
  select(title: string, options: string[]): Promise<string | undefined>;
  input(title: string, placeholder?: string): Promise<string | undefined>;
  notify(message: string, type?: "info" | "warning" | "error"): void;
}

export interface PipelineRuntime {
  workspace: string;
  mode: "tui" | "rpc" | "json" | "print";
  ui: ApprovalUI;
  tool?: JudgeInput["tool"];
  userRequest?: string;
  signal?: AbortSignal;
  assess?: (input: JudgeInput, signal: AbortSignal) => Promise<RiskAssessment>;
  audit?: (event: AuditEvent) => Promise<void>;
  modelIdentifier?: string;
  decisionCache?: Map<string, Promise<RiskAssessment>>;
  approvalQueue?: ApprovalQueue;
}

export interface ApprovalQueue {
  tail: Promise<void>;
}

export interface ApprovalResult {
  block?: true;
  reason?: string;
}

const ALLOW = "Allow once";
const DENY = "Deny";
const DENY_WITH_INSTRUCTIONS = "Deny with instructions";

export async function approveToolCall(call: ToolCall, runtime: PipelineRuntime): Promise<ApprovalResult> {
  const policy = await classifyToolCall(call, runtime.workspace);
  if (policy.route === "safe-bypass") return {};

  const workingDirectory = await canonicalPath(runtime.workspace);
  let assessment: RiskAssessment = {
    riskLevel: "high",
    operation: policy.operation,
    riskExplanation: policy.riskExplanation,
  };
  let judgeLatencyMs: number | undefined;
  let judgeOutcome: AuditEvent["outcome"] | undefined;
  let judgeSource: AuditEvent["decisionSource"] = "ai-judge";
  if (policy.route === "candidate" && runtime.assess) {
    const key = decisionKey(call, workingDirectory);
    const cached = runtime.decisionCache?.get(key);
    let cachedAssessment: RiskAssessment | undefined;
    if (cached) {
      try {
        const candidate = await (runtime.signal ? withAbort(cached, runtime.signal) : cached);
        if (candidate.riskLevel !== "high") cachedAssessment = candidate;
      } catch {
        if (runtime.signal?.aborted) throw runtime.signal.reason;
      }
    }
    if (cachedAssessment) {
      assessment = cachedAssessment;
      judgeOutcome = "allowed";
      judgeSource = "cache";
    } else {
      const started = performance.now();
      const pending = assessCandidate(call, workingDirectory, runtime);
      runtime.decisionCache?.set(key, pending);
      try {
        assessment = await pending;
        judgeOutcome = assessment.riskLevel === "high" ? "approval-required" : "allowed";
      } catch (error) {
        if (runtime.signal?.aborted) throw runtime.signal.reason;
        judgeOutcome = error instanceof DOMException && error.name === "TimeoutError" ? "timeout" : "judge-error";
        assessment.riskExplanation = "Risk assessment failed, so Sentinel requires human Approval.";
      } finally {
        if (assessment.riskLevel === "high" && runtime.decisionCache?.get(key) === pending) runtime.decisionCache.delete(key);
        judgeLatencyMs = Math.round(performance.now() - started);
      }
    }
  } else if (policy.route === "candidate") {
    judgeOutcome = "judge-error";
    assessment.riskExplanation = "Risk assessment failed, so Sentinel requires human Approval.";
  }

  const event = (decisionSource: AuditEvent["decisionSource"], outcome: AuditEvent["outcome"]): AuditEvent => ({
    timestamp: new Date().toISOString(),
    workingDirectory,
    toolName: call.toolName,
    arguments: call.input,
    riskLevel: assessment.riskLevel,
    operationSummary: assessment.operation,
    riskExplanation: assessment.riskExplanation,
    decisionSource,
    outcome,
    modelIdentifier: runtime.modelIdentifier ?? "unavailable",
    ...(judgeLatencyMs === undefined ? {} : { judgeLatencyMs }),
  });

  await audit(runtime, event(policy.route === "hard-guard" ? "hard-guard" : judgeSource, policy.route === "hard-guard" ? "approval-required" : judgeOutcome!));

  if (policy.route !== "hard-guard" && assessment.riskLevel === "low" && judgeOutcome === "allowed") return {};
  if (policy.route !== "hard-guard" && assessment.riskLevel === "medium") {
    runtime.ui.notify(`Sentinel: ${assessment.operation} (${assessment.riskExplanation})`, "warning");
    return {};
  }

  const result = runtime.approvalQueue
    ? await queueApproval(runtime.approvalQueue, runtime.signal, () => requestApproval(policy, assessment, runtime))
    : await requestApproval(policy, assessment, runtime);
  await audit(runtime, event(runtime.mode === "print" || runtime.mode === "json" ? "runtime" : "human", result.block ? "denied" : "allowed"));
  return result;
}

async function audit(runtime: PipelineRuntime, event: AuditEvent): Promise<void> {
  if (!runtime.audit) return;
  try {
    await runtime.audit(event);
  } catch {
    if (runtime.mode === "tui" || runtime.mode === "rpc") runtime.ui.notify("Sentinel could not write the audit trail.", "error");
  }
}

function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

async function assessCandidate(call: ToolCall, workingDirectory: string, runtime: PipelineRuntime): Promise<RiskAssessment> {
  const signal = runtime.signal
    ? AbortSignal.any([runtime.signal, AbortSignal.timeout(15_000)])
    : AbortSignal.timeout(15_000);
  signal.throwIfAborted();
  return validateRiskAssessment(
    await withAbort(
      runtime.assess!(
        {
          call,
          tool: runtime.tool ?? { description: "No tool definition is available.", parameters: {} },
          workspace: workingDirectory,
          userRequest: runtime.userRequest ?? "No user request is available.",
        },
        signal,
      ),
      signal,
    ),
  );
}

async function queueApproval<T>(queue: ApprovalQueue, signal: AbortSignal | undefined, action: () => Promise<T>): Promise<T> {
  const previous = queue.tail.catch(() => undefined);
  let release!: () => void;
  const turn = new Promise<void>((resolve) => { release = resolve; });
  queue.tail = previous.then(() => turn);
  try {
    await (signal ? withAbort(previous, signal) : previous);
    signal?.throwIfAborted();
    return await action();
  } finally {
    release();
  }
}

function decisionKey(call: ToolCall, workingDirectory: string): string {
  return `${call.toolName}\0${workingDirectory}\0${stableJson(call.input)}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

async function requestApproval(
  policy: PolicyDecision,
  assessment: RiskAssessment,
  runtime: PipelineRuntime,
): Promise<ApprovalResult> {
  runtime.signal?.throwIfAborted();
  const reason = `${policy.route === "hard-guard" ? "Hard Guard" : "Candidate Operation"}: ${assessment.operation}. Risk: ${assessment.riskExplanation}`;
  if (runtime.mode === "print" || runtime.mode === "json") {
    return { block: true, reason: `Sentinel blocked an operation requiring Approval in ${runtime.mode} mode. ${reason}` };
  }

  const choice = await runtime.ui.select(`Sentinel Approval\n\nOperation: ${assessment.operation}\nRisk: ${assessment.riskExplanation}`, [
    ALLOW,
    DENY,
    DENY_WITH_INSTRUCTIONS,
  ]);
  if (choice === ALLOW) return {};
  if (choice === DENY_WITH_INSTRUCTIONS) {
    const instruction = await runtime.ui.input("How should the agent replan?", "Use a safer alternative");
    if (instruction?.trim()) return { block: true, reason: `Sentinel denied the Tool Call. User instruction: ${instruction.trim()}` };
  }
  return { block: true, reason: `Sentinel denied the Tool Call. ${reason}` };
}
