import { classifyToolCall, type PolicyDecision, type ToolCall } from "./policy.ts";

export type RiskLevel = "low" | "medium" | "high";

export interface RiskAssessment {
  riskLevel: RiskLevel;
  operation: string;
  riskExplanation: string;
}

export interface ApprovalUI {
  select(title: string, options: string[]): Promise<string | undefined>;
  input(title: string, placeholder?: string): Promise<string | undefined>;
  notify(message: string, type?: "info" | "warning" | "error"): void;
}

export interface PipelineRuntime {
  workspace: string;
  mode: "tui" | "rpc" | "json" | "print";
  ui: ApprovalUI;
  assess?: (call: ToolCall) => Promise<RiskAssessment>;
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
      assessment = await runtime.assess(call);
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
