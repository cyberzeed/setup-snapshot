# setup-snapshot

Pack a Claude Code setup into one verifiable archive, move it over any transport, and install it on another machine only after reviewing a risk-tiered plan.

```
sender:   create  ->  push  ->  ticket (5 lines, no secrets)
receiver: paste ticket  ->  plan (verify sha256, check every file)  ->  apply approved categories  ->  rollback if needed
```

Status: v0.1.0, pre-release. macOS and Linux, Python 3.9+ standard library only. No server, no account, no telemetry.

## What goes in a snapshot

| Category | From | Risk |
| --- | --- | --- |
| instructions | `~/.claude/CLAUDE.md` | medium |
| skill | `~/.claude/skills/<name>/` | low, or high with scripts / `allowed-tools: Bash` |
| agent, command, output-style | `~/.claude/agents/`, `commands/`, `output-styles/` | medium / medium / low |
| settings | allowlisted keys of `settings.json` | low |
| hooks | `hooks` and `statusLine` of `settings.json` | high |
| keybindings | `~/.claude/keybindings.json` | low |
| notes (opt-in) | dirs you list in the profile | medium |
| plugin | metadata only: marketplace, id, commit | high, receiver reinstalls |
| mcp | metadata only: command, args, env key names; plain flag values (`true`, `0`, `8080`) under non-secret names | high, every other env value dropped |

Never collected: `.credentials.json`, `projects/` (sessions, transcripts), history, todos, plugin caches, `.env*`, `*.pem`, `id_*`, anything with `credentials` in the name. Every collected file is secret-scanned; a hit aborts the build and names `path:line: rule`, never the value.

The archive is a plain `tar.gz` with `manifest.json` and `payload/`. Open it with `tar` to see exactly what is inside.

## Install

Install from a clone checked out at a release tag, never from `main`. `claude plugin marketplace add` has no documented way to pin a tag, so the clone is what pins the version.

```sh
git clone --branch v0.1.0 --depth 1 https://github.com/cyberzeed/setup-snapshot.git ~/.local/share/setup-snapshot
git -C ~/.local/share/setup-snapshot rev-parse HEAD    # compare with the commit on the release page
claude plugin marketplace add ~/.local/share/setup-snapshot
claude plugin install setup-snapshot@setup-snapshot
```

Upgrade: read the changelog and the diff, then check out the new tag and refresh the marketplace.

```sh
cd ~/.local/share/setup-snapshot
git fetch --depth 1 origin tag v0.2.0
git diff v0.1.0 v0.2.0 --stat
git checkout v0.2.0
claude plugin marketplace update setup-snapshot
claude plugin update setup-snapshot@setup-snapshot
```

Without the plugin, run the CLI straight from the clone: `python3 -I ~/.local/share/setup-snapshot/bin/setup-snapshot --help`.

## Use

Sender:

```sh
setup-snapshot create --dry-run                       # see what would leave the machine
setup-snapshot create --name my-mac --out ~/snaps
setup-snapshot push ~/snaps/my-mac.snap.tar.gz ssh://me@linuxbox/home/me/snaps/
# prints the ticket
```

Receiver (or paste the ticket into Claude Code with the plugin installed):

```sh
setup-snapshot plan  --ticket ticket.txt
setup-snapshot apply --ticket ticket.txt --approve all --approve-high skill
setup-snapshot rollback
```

Profile (`~/.config/setup-snapshot/profile.json`), all keys optional:

```json
{
  "categories": ["instructions", "skill", "agent", "command", "output-style", "settings", "hooks", "keybindings", "plugin", "mcp"],
  "skills": "*",
  "skip_skills": ["graphify"],
  "notes_dirs": ["notes"],
  "settings_keys": ["env", "permissions", "model", "effortLevel", "theme", "outputStyle"],
  "allowed_email_domains": ["example.com"]
}
```

## Transports

| Locator | Tool | Private in transit |
| --- | --- | --- |
| `file:///path/` (also synced cloud folders) | copy | no, stored as-is |
| `ssh://user@host[:port]/path/` | `scp` | yes |
| `rsync+ssh://user@host[:port]/path/` | `rsync` over SSH | yes |
| `s3://bucket/prefix/` | `aws s3 cp` | no, stored as-is |
| `https://...` (fetch only) | stdlib | yes in transit, stored as-is |

v0.1 has no encryption. `push` refuses to put a snapshot holding CLAUDE.md or notes on unencrypted storage unless you pass `--confirm-plaintext`. Encryption (age) and signatures (`ssh-keygen -Y`) are planned for v1.1 as outer layers.

## Security

Installing a snapshot is installing code. See [SECURITY.md](SECURITY.md) for the threat model. In short: the receiver trusts only the sha256 in the ticket; the ticket is parsed by the CLI, never interpreted by Claude; high-risk items need a separate approval; plugin and MCP commands are printed, never run; every apply is backed up and reversible.

## Development

```sh
python3 -I -m unittest discover -s tests
```

## License

MIT
