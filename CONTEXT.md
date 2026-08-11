# Domain Glossary

- **Sentinel**: The safety layer that decides whether a Tool Call may proceed.
- **Tool Call**: An operation requested by the model through a Pi tool.
- **Workspace**: The canonical filesystem tree rooted at Pi's current working directory.
- **Safe Bypass**: A Tool Call proven safe enough to proceed without a Risk Level or Approval.
- **Candidate Operation**: A Tool Call that is not eligible for a Safe Bypass and is not necessarily a Hard Guard.
- **Hard Guard**: A deterministic rule that always requires human Approval for a known catastrophic operation.
- **AI Judge**: The active model acting as an ergonomic risk classifier for a Candidate Operation or as a preliminary reviewer whose output cannot downgrade a Hard Guard.
- **Risk Level**: The low, medium, or high risk assigned to a Candidate Operation.
- **Approval**: A human decision to allow one Tool Call, deny it, or deny it with replanning instructions.
- **Audit Event**: A record of a meaningful Sentinel decision.
