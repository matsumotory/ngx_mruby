@AGENTS.md

## Claude Code notes

- Parallel work: use one `git worktree` per task (`git worktree add -b claude/<topic> <dir> origin/<base>`).
  Each worktree has its own `build/`, but `test.sh` still uses fixed ports and kills
  all `nginx` processes, so run `test.sh` in only one worktree at a time.
- Long builds: a full `sh test.sh` takes minutes. Run it in the background with the
  output redirected to a log file, and read the log when it finishes.
- After the first full run, iterate with `ONLY_BUILD_NGX_MRUBY=1 sh test.sh`.
- The memory soak test (`sh test/soak/run.sh`, see AGENTS.md) also builds for
  minutes the first time: run it in the background the same way, and not while
  `test.sh` runs on the same machine.
- Pull requests: `gh pr create --draft --base <master|next>`, with a body that follows
  every section of `.github/PULL_REQUEST_TEMPLATE.md`. Have a separate agent review
  the PR with the checklist in AGENTS.md, post its findings as a PR comment, and
  merge with a merge commit when the conditions in AGENTS.md hold. Do not tag or
  release.
