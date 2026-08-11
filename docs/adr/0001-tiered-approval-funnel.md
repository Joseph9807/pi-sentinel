# ADR 0001: Tiered Approval Funnel

## Status

Accepted

## Context

Routine coding should remain fast, but model-generated operations can damage the system or user data. Deterministic rules are dependable but cannot classify every operation without excessive prompts. Model judgment is flexible but is not a security boundary.

## Decision

Sentinel routes every Tool Call through one funnel:

1. A conservatively proven Safe Bypass proceeds immediately.
2. A Hard Guard always requires human Approval and cannot be downgraded.
3. A Candidate Operation may receive a Risk Level from the AI Judge; high risk and judge failure require Approval.

A Hard Guard may use the AI Judge to provide preliminary review context before Approval, but the review cannot downgrade its Risk Level or bypass Approval.

When no interactive Approval is possible, operations requiring a decision are blocked.

## Consequences

Routine reads and Workspace-contained edits avoid interruption. Known catastrophic operations remain under human control even when model judgment is wrong. Ambiguous operations may add latency or require Approval, favoring deterministic safety over uninterrupted automation.
