@AGENTS.md

## Claude Code notes

- Parallel work: use one `git worktree` per task, under `.claude/worktrees/`
  (`git worktree add -b claude/<topic> .claude/worktrees/<topic> origin/<base>`).
  Each worktree has its own `build/`. To run `test.sh` in two worktrees at the
  same time, give each a different `TEST_SH_PORT_OFFSET` (for example 0 and 1000).
- Temporary files (PR bodies, commit message drafts, scratch scripts, raw outputs of
  checks) go under `.claude/tmp/<session>/`, not under `/tmp`. Both `.claude/worktrees/`
  and `.claude/tmp/` are in `.gitignore`.
- Long builds: a full `sh test.sh` takes minutes. Run it in the background with the
  output redirected to a log file, and read the log when it finishes.
- After the first full run, iterate with `ONLY_BUILD_NGX_MRUBY=1 sh test.sh`.
- The memory soak test (`sh test/soak/run.sh`, see AGENTS.md) also builds for
  minutes the first time: run it in the background the same way, and not while
  `test.sh` runs on the same machine. The performance comparison
  (`sh test/perf/compare.sh BASE_DIR`) builds two trees: the same applies.
- Pull requests: `gh pr create --draft --base <master|next>`, with a body that follows
  every section of `.github/PULL_REQUEST_TEMPLATE.md`. Have a separate agent review
  the PR with the checklist in AGENTS.md, post its findings as a PR comment, and
  merge with a merge commit when the conditions in AGENTS.md hold. Do not tag or
  release.
