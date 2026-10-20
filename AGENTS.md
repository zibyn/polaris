## Agent skills

### Issue tracker

Issues live in GitHub Issues on `zibyn/polaris` (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Research

Run research agents in the current working tree, not in an isolated worktree. They only write `docs/research/<topic>.md` and never run git: no branch, no commit. The user commits the file.

### Prototypes

Prototypes live only on remote `prototype/<name>` branches, linked from the implementation issue. Never merge them into main, and don't keep a local `prototypes/` directory.
