# CLAUDE.md — homelab-harden

Conventions for working on this repo. Follow these on every change.

## Scope discipline
- This is a fixed-scope v0.1: a read-only audit of the local Linux host against a
  built-in ruleset. Out of scope and binding: auditing a remote host over SSH,
  auto-fixing anything, config files / ignore rules, a daemon or scheduling, non-Linux
  targets. If something beyond scope seems warranted, add it to the README roadmap.
- Stick to the stack: Python 3.11+, zero runtime dependencies (stdlib only); pytest +
  ruff for dev. Do not add a dependency without asking me first.

## Read-only, always
- This tool never modifies the system. It reads files and runs read-only commands
  (`sshd -T`, `ufw status`, `ss`, `systemctl is-active`, etc.). No command that changes
  state may ever be added to `collect`. Every fix is advice printed to the user.

## Code style
- Write idiomatic, concise Python. Prefer the simplest construct that reads clearly.
- No redundant or explanatory comments. Do not narrate what the code already says, and
  do not leave notes addressed to an AI. Comment only the non-obvious: a subtle decision,
  a workaround, or a "why". Prefer clear names over comments.
- No docstrings on trivial functions. Use type hints on signatures and dataclasses.
- Code must pass `ruff check` and `ruff format` with no warnings.
- No dead code, no commented-out code, no scattered TODOs.
- Keep functions small and single-purpose, matching the module layout:
  facts / parsers / collect / rules / render / cli.

## Project-specific rules
- Separate concerns strictly: `collect` is the only OS-specific code (Linux commands and
  file reads). `parsers` and `rules` are pure functions over data. This keeps the logic
  testable on any OS and keeps the platform-specific surface tiny.
- Every subprocess call uses an explicit timeout so one hung command can't stall the audit.
- `collect` degrades gracefully: any command or file that is missing or unreadable becomes
  a `note` on the report, never a crash. Checks that need root say so when not root.
- Every rule has a stable `HHNNN` id and carries a concrete `fix`.
- Severity means something: `high` = real exposure, `medium` = weak default worth fixing,
  `low` = hygiene. Don't inflate. Only flag explicit misconfigurations, never absent-and-
  therefore-unknown state (e.g. an unset SSH directive is not a finding).
- Exit-code contract: 0 = clean or under `--fail-on`, 1 = findings at/above threshold
  (default `high`), 2 = usage error.

## Tests
- Every logic module (parsers, rules, cli) has tests. Tests use fixture strings and
  sample Facts, never a real host — they must pass on a laptop with no Linux, no root,
  no network. New rules ship with a case that fires and a case that does not over-fire.
- Tests must pass before a change is considered done.

## Git
- Commit messages are concise and imperative ("add fail2ban check"), with no filler.
- Do not commit, push, publish, or open a pull request without my explicit approval.
- Commit/PR attribution is disabled via ~/.claude/settings.json; do not reintroduce it.

## Working with me
- I am learning Python. When you write or change anything non-trivial, give me a short
  plain-English explanation in chat, NOT as code comments. The committed code stays clean;
  the teaching goes in the conversation.
- Build in small, focused steps. Be direct. Do not pad responses.
