@AGENTS.md

## Claude Code notes

- Shared handoff and ownership follow `AGENTS.md` and "Continuing shared
  work" in `docs/DEVELOPMENT.md`, also when Codex or a human takes over.
  The paths below are local Claude conventions, not handoff evidence.
- Parallel work: use one `git worktree` per task, under `.claude/worktrees/`
  (`git worktree add -b claude/<topic> .claude/worktrees/<topic> origin/<base>`).
  Each worktree has its own `build/`, but `test.sh` still uses fixed ports and kills
  all `nginx` processes, so run `test.sh` in only one worktree at a time.
- Temporary files (PR bodies, commit message drafts, scratch scripts, raw outputs of
  checks) go under `.claude/tmp/<session>/`, not under `/tmp`. Both `.claude/worktrees/`
  and `.claude/tmp/` are in `.gitignore`.
- Long builds: a full `sh test.sh` takes minutes. Run it in the background with the
  output redirected to a log file, and read the log when it finishes.
- After the first full run, iterate with `ONLY_BUILD_NGX_MRUBY=1 sh test.sh`.
- Pull requests: `gh pr create --draft --base <master|next>`, with a body that follows
  every section of `.github/PULL_REQUEST_TEMPLATE.md`. Have a separate agent review
  the PR with the checklist in AGENTS.md, post its findings as a PR comment, and
  merge with a merge commit when the conditions in AGENTS.md hold. Do not tag or
  release.
