import { canonicalPath, classifyToolCall, type PolicyDecision, type ToolCall } from "./policy.ts";
import { type JudgeInput, type RiskAssessment, validateRiskAssessment } from "./judge.ts";

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

  let assessment: RiskAssessment = {
    riskLevel: "high",
    operation: policy.operation,
    riskExplanation: policy.riskExplanation,
  };
  if (policy.route === "candidate" && runtime.assess) {
    try {
      const signal = runtime.signal
        ? AbortSignal.any([runtime.signal, AbortSignal.timeout(15_000)])
        : AbortSignal.timeout(15_000);
      signal.throwIfAborted();
      assessment = validateRiskAssessment(
        await withAbort(
          runtime.assess(
            {
              call,
              tool: runtime.tool ?? { description: "No tool definition is available.", parameters: {} },
              workspace: await canonicalPath(runtime.workspace),
              userRequest: runtime.userRequest ?? "No user request is available.",
            },
            signal,
          ),
          signal,
        ),
      );
    } catch {
      assessment.riskExplanation = "Risk assessment failed, so Sentinel requires human Approval.";
    }
  }

  if (policy.route !== "hard-guard" && assessment.riskLevel === "low") return {};
  if (policy.route !== "hard-guard" && assessment.riskLevel === "medium") {
    runtime.ui.notify(`Sentinel: ${assessment.operation} (${assessment.riskExplanation})`, "warning");
    return {};
  }

  return requestApproval(policy, assessment, runtime);
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

async function requestApproval(
  policy: PolicyDecision,
  assessment: RiskAssessment,
  runtime: PipelineRuntime,
): Promise<ApprovalResult> {
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
