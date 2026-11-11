<!--
Fill in every section; write "n/a" where one does not apply.
Do not describe security vulnerabilities here. Report them privately (see SECURITY.md).
-->

## Summary

<!-- What does this change, and why? Link related issues. -->

## Target branch

- [ ] `master`: 2.x fix or maintenance (until v3 is promoted)
- [ ] `next`: v3 development
- Backport to 2.x needed? <!-- yes / no, and why -->

## How was this tested

<!--
Exact commands and their results, e.g. `sh test.sh`, `BUILD_DYNAMIC_MODULE=1 sh test.sh`,
with the nginx version used, the commit each ran on and the machine.
Every kind of check that CI runs for the change runs locally first ("Build and test" in AGENTS.md
lists them: the suite, the sanitizers and valgrind, the callgrind comparison, the soak, the steps of
examples/start, nginx-tests, the site's checks, zizmor). A check that could not run locally: what was
tried, and why it did not run.
Bug fixes: the regression test is the first commit and the fix the second; quote `sh test.sh`
(or the valgrind/sanitizer report) at each commit, failing at the first and passing at the second.
-->

## Memory / sanitizer checks (C changes)

<!--
Required for a change of C code (`src/`, the C sources of `mrbgems/`, `mruby/`,
`dependence/`) or of the build; "n/a" otherwise. Run both locally before marking
the PR ready, on Linux or in a Linux container on macOS (docs/test/README.md),
each in a checkout of its own. That CI runs the sanitizer cell and the cell under
valgrind does not replace these runs.
- Sanitizers (ASan with LeakSanitizer, and UBSan), as "Running the tests under
  AddressSanitizer and UndefinedBehaviorSanitizer" in docs/test/README.md says:
  the command, the commit, the machine (architecture, container image), the
  result of `test.sh`, and the output of the grep of that section on the logs
  (no line).
- valgrind with the options of "valgrind in CI": the command, the commit, the
  machine, the result of `test.sh`, and the `ERROR SUMMARY` line of every log
  (each with 0 errors).
-->

- Sanitizers:
- valgrind:

## Leak / performance impact

<!--
Required when async, filter or GC-related code is touched: what was measured, and how.
Required as well when the change touches an input of the measured binary ("Design principles" in
`AGENTS.md` lists them): the callgrind comparison that you ran locally (`sh test/perf/compare.sh`,
in a Linux container on macOS) goes here before the PR is marked ready, with the header lines of
report.txt, the table, the base and head commits that were compared and the machine. Once the PR
is ready, add the run of the `perf` job and the base and head commits that its log prints.
-->

- Local comparison:
- `perf` job:

## Compatibility / behavior changes

<!--
Changes to directives, the Ruby API, handler return values, build options or supported versions.
Can a configuration, script or build observe a difference from the last release (status, headers or
body of a response, what a Ruby method returns or raises, which handler runs, whether `nginx -t`
accepts a configuration, a raised build requirement, a dropped stable nginx line or platform, the
bundled mruby or default mrbgems)? A bug fix counts when the old behavior could be relied on. An
addition that leaves existing configurations, scripts and builds behaving as before goes under
"New features" instead. docs/releases/README.md says what counts and has more examples.
For each such change, fill in the lines below with the same text as its entry under
"Behavior changes: read before upgrading" in docs/releases/<version>.md. "Why it changed"
gives the defect (or, for a change that fixes no defect, "The reason:"), why the old behavior
could not be kept (in an entry with "The reason:", what keeping it would have cost), and what
the documentation promised; see "Template" in docs/releases/README.md.
The same entry in Japanese goes in docs/releases/<version>.ja.md.
Write "n/a" in them when nothing changes.
-->

- Before:
- Now:
- Why it changed:
  - The defect:
  - Why the old behavior could not be kept:
  - What the documentation promised:
- Affected:
- What to do:

- [ ] `docs/releases/<version>.md` has an entry under "Behavior changes: read before upgrading" for every change above, and `docs/releases/<version>.ja.md` has the same entry in Japanese
- [ ] No behavior change that a configuration, script or build can observe

- Base `master`: does the change stay within the 2.x policy in AGENTS.md (stability and security fixes; observable behavior changes only as far as the fix of a defect requires; new behavior, API cleanups and features go to `next`)? <!-- yes / no, and why; n/a for base `next` -->

## Checklist

- [ ] Patches are in `src/` (C) or `mrbgems/` (Ruby).
- [ ] Tests are in `test/`. Please see the [test docs](https://github.com/matsumotory/ngx_mruby/tree/master/docs/test).
- [ ] Docs are updated in `docs/` if you change features such as the [build system](https://github.com/matsumotory/ngx_mruby/tree/master/docs/install), [Ruby methods and classes](https://github.com/matsumotory/ngx_mruby/tree/master/docs/class_and_method) or [nginx directives](https://github.com/matsumotory/ngx_mruby/tree/master/docs/directives).

## AI assistance

<!-- Was an AI tool used? Which one, and for what (code, tests, docs, PR text)? Did a human review the result? -->

<!-- When handing this PR to another session, follow "Continuing shared work"
in docs/DEVELOPMENT.md. Keep the evidence above current and leave a dated
checkpoint comment with head/base, decisions, remaining work, checks not run
or still running, and the next step. Use public repository/PR/run references;
do not paste private logs, local absolute paths or tool memory. -->
