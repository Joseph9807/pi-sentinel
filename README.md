# pi-sentinel

`pi-sentinel` is a macOS safety gate for model-issued [Pi](https://github.com/earendil-works/pi) Tool Calls. It keeps routine coding uninterrupted while requiring human Approval for operations that may cause serious damage or data loss.

It is not a sandbox or a complete security boundary.

## Requirements

- macOS
- Node.js 22.19 or newer
- Pi 0.84.1 or newer

## Installation

Install the package through Pi's npm package workflow:

```sh
pi install npm:pi-sentinel@0.1.0
```

To load a local checkout without installing it:

```sh
pi -e /absolute/path/to/pi-sentinel
```

## Behavior

Sentinel observes model-issued Tool Calls before execution and routes them through three layers:

1. **Safe Bypass**: clearly read-only built-in tools, a conservative set of read-only shell commands, and ordinary writes or edits inside the canonical Workspace proceed immediately. They do not call the model, prompt the user, or create Audit Events.
2. **Hard Guard**: known catastrophic operations always require human Approval. These include destructive Git cleanup, deleting protected roots or Git metadata, disk erase or partition commands, and direct `curl`/`wget`-to-shell execution. The AI Judge cannot downgrade a Hard Guard.
3. **AI Judge**: every other Candidate Operation is classified by the active Pi model. A failed, timed-out, malformed, or unavailable assessment fails closed and requires Approval.

### Risk Levels

- **Low**: proceeds silently.
- **Medium**: proceeds with a non-blocking warning.
- **High**: requires human Approval.

Repeated identical low- and medium-risk conclusions may be reused within one session. High-risk and Hard Guard decisions are never approval-cached, and a new or replaced session clears the cache.

### Human Approval

Interactive Pi modes show the operation and risk explanation, then offer:

- **Allow once**: execute this Tool Call only.
- **Deny**: block this Tool Call.
- **Deny with instructions**: block the call and return replanning guidance to the agent.

Closing or cancelling the dialog denies the call. Approval dialogs are serialized when parallel Tool Calls need attention. In print and JSON modes, calls requiring Approval are blocked instead of waiting for interaction.

### Remote Scripts

Direct literal HTTP(S) URLs used by `curl` or `wget` and piped to a shell remain Hard Guard operations. Sentinel may fetch a preview with Node's HTTP client to provide preliminary AI review context. It rejects localhost and non-public destinations, rechecks bounded redirects, accepts text content only, times out the request, and reads at most the first 64KB.

Remote-script review is preliminary. It is not static analysis, trust certification, or proof that a script is safe. Unsupported syntax, dynamic URLs, private destinations, download failures, and truncated previews still require Approval.

## Data Sent to the Model Provider

The AI Judge uses Pi's active model and existing authentication. For a Candidate Operation, Sentinel may send the active model provider:

- the Tool Call name, description, parameter schema, and arguments;
- the canonical working directory;
- the latest user request; and
- for a supported public remote script, up to the first 64KB of its content.

Sentinel does not send the complete conversation. Tool arguments and remote-script previews are marked as untrusted content in the judge prompt, but the provider still receives that content. Review your active provider's privacy and retention terms before use.

## Audit Log

Meaningful AI, cache, Hard Guard, runtime, and human decisions are written as JSON Lines to:

```text
$PI_CODING_AGENT_DIR/sentinel-audit.jsonl
```

The default location is `~/.pi/agent/sentinel-audit.jsonl`. Each event records the Workspace, tool, risk, explanation, decision source, outcome, model identifier, timing when available, a SHA-256 hash of the redacted arguments, and at most 1,024 characters of their serialized preview.

Argument fields whose keys contain common credential terms such as `password`, `token`, `key`, `secret`, `authorization`, or `authentication` are recursively redacted before logging. This is a best-effort key-name filter, not secret detection.

The active log is limited to 1MB and keeps two 1MB rotations (`.1` and `.2`), for approximately 3MB total. Safe Bypasses are not logged. An audit-write failure does not change the Tool Call decision and is reported non-disruptively where a UI is available.

## First-Release Limitations

- macOS only; Linux, Windows, and cross-platform policy abstractions are out of scope.
- AI approval is an ergonomic classifier, not a sandbox. Use OS-level isolation when a real security boundary is required.
- Sentinel does not protect against a malicious local user, a compromised Pi process, or code already running with the user's permissions.
- Sensitive-read protection, secret-exfiltration prevention, prompt-injection detection, dependency malware detection, and general supply-chain security are out of scope.
- Direct user `!` and `!!` shell commands are not intercepted; Sentinel observes model-issued Tool Calls only.
- Remote-script inspection supports only one direct literal public HTTP(S) URL passed from `curl` or `wget` to a shell. Other download-then-execute flows are not inspected.
- Remote scripts are never automatically approved, even when preliminary AI review appears safe.
- Audit redaction recognizes common sensitive key names only. Sensitive values under other keys may appear in the bounded preview.
- There are no user-defined rules, thresholds, protected paths, model choices, log settings, allowlists, or denylists.
- There are no persistent or per-project approvals, cross-session caches, policy editor, configuration file, management command, status screen, log viewer, or custom settings UI.
- Denial does not rewrite arguments or start another conversation turn; only **Deny with instructions** returns guidance for replanning.
- Interactive high-risk operations are not automatically denied; the user remains responsible for the Approval decision.
- Sentinel is not an enterprise administration, centralized policy, compliance, or team audit-ingestion system.
- Pi versions older than 0.84.1 are unsupported.

## Development

```sh
npm install
npm run typecheck
npm test
npm pack --dry-run
```

## License

[MIT](LICENSE)
