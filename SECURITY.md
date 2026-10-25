# Security model

A snapshot can contain hooks, skill scripts, MCP server definitions and CLAUDE.md instructions: installing one is installing code that will run, or steer what runs, on the receiving machine. setup-snapshot trusts only two things: the sha256 in the ticket and the receiver's own approvals.

| Threat | Defence |
| --- | --- |
| A secret leaves the sender (token pasted into CLAUDE.md, a note, a skill) | Fail-closed scan on every collected file; secret-named `env` keys rejected; hard exclusion list; notes opt-in. Findings show `path:line: rule`, never the value. |
| Archive tampered with in storage or transit | Ticket sha256 checked before the archive is decompressed; every file checked against the manifest after. |
| Malicious archive structure (`..`, absolute paths, symlinks, hardlinks, devices, decompression bombs) | Hand-written extraction: regular files only, names under `manifest.json`/`payload/`, size, count and ratio limits, exact match with the manifest. |
| Prompt injection through the ticket | Strict `key: value` parser in the CLI; any extra text or key rejects the ticket. The skill tells Claude to pass the ticket through unchanged. |
| Prompt injection through content | Plan shows content as data; medium and high tiers need approval; the skill tells Claude not to follow instructions in snapshot content. |
| Code execution on the receiver (hooks, MCP, script skills) | `high` tier: applied only when the category is named in `--approve-high`; never covered by `--approve all`. Plugin and MCP commands are printed, never executed. |
| Command injection via manifest fields | Plugin and MCP names validated; no control characters anywhere in the manifest; printed commands are shell-quoted. |
| Credentials in a locator | Locators with `user:pass@` or credential query parameters are rejected unless `--allow-presigned` is passed. |
| Weakening the receiver's policy | Settings merge never removes the receiver's list entries such as `permissions.deny`. |
| A bad apply | Backup of every changed or removed file before the change; `rollback` restores byte for byte. |

Out of scope for v0.1: proving who created a snapshot (signatures) and confidentiality on non-SSH transports (encryption). Share tickets only with people you trust, and move snapshots that include CLAUDE.md or notes over SSH.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
