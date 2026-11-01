# Developing ngx_mruby

Development procedures for human contributors and coding agents.

Before you change the C module (`src/`), the gems in `mrbgems/` or the
build, read [Design principles](../AGENTS.md#design-principles) in
AGENTS.md: the owner's decisions (one `mrb_state` per worker, no blocking,
keep the existing performance and measure it) and how sessions apply them,
including which changes are measured and how.

## Continuing shared work

[AGENTS.md](../AGENTS.md#session-handoff) defines the shared handoff rules.
The current queue is [HANDOFF.md](https://github.com/matsumotory/ngx_mruby/blob/next/docs/HANDOFF.md) on `next`; the active PR holds
the detailed evidence. Claude's and Codex's private memories are optional
context, not prerequisites for continuing work.

1. Read AGENTS, the relevant plan, code and tests, then HANDOFF and the PR's
   latest body, review comments and CI results. Fetch `origin` and verify
   the recorded base and head; a dated snapshot is not a live branch tip.
   Search open PRs and all topic branches, including `claude/*` and
   `codex/*`, before starting a queue item.
   For site, navigation or user-facing documentation work, read
   [Site design acceptance](proposals/site.md#site-design-acceptance) before
   editing. Follow its complete reader journey, including generated 2.x entry
   pages when affected; a homepage-only screenshot is not sufficient.
2. Inspect `git worktree list`, the intended worktree's branch and
   `git status --short`. Reuse the existing task worktree when possible.
   Confirm that its previous writer and local build/preview processes have
   stopped before taking over; external CI may continue and should be
   inspected rather than restarted. Preserve uncommitted work. If another
   task needs a worktree, create its own `<tool>/<topic>` branch from the
   appropriate base under the branch rules in AGENTS. Do not reset a shared
   checkout to make its files match a handoff.
3. Claim an existing PR with a comment naming the head being taken over.
   For new work, open a PR as a draft once the scoped changes are
   reviewable, and mark it ready for review when the work and its local
   checks are done ("Branches and pull requests" in AGENTS: a draft runs no
   CI, ready starts it, and ready is not approval).
   Keep its template sections current as the head or evidence changes;
   update the queue through HANDOFF as AGENTS requires. Use commit messages
   to preserve the problem, reasoning, relevant tradeoffs and validation,
   with explicit limits when something was not tested.
4. Before stopping or transferring work, put a dated checkpoint in that PR:
   **scope and decisions** (link the accepted decision, distinguish open
   questions); **state** (branch, head/base, draft or ready and why, whether a
   CI run of the head exists, stage and remaining diff);
   **evidence** (commands, environment/nginx version, tested commits,
   results and run/review links); **unfinished work** (not run, in progress,
   failed, denied or uncertain outcomes); **next step** (the concrete action
   and its prerequisite). Confirm which writer has stopped. If there is no
   PR yet, record the public scope and next step in HANDOFF via the normal
   documentation PR; preserve unfinished files locally without publishing
   raw scratch data. A successor must not assume unpushed work is available
   on another machine.
5. Keep temporary logs, screenshots, PR drafts and personal references
   outside the repository or in narrowly ignored directories. Before each
   commit inspect `git status --short --untracked-files=all`,
   `git check-ignore -v <generated-path>`, `git ls-files <generated-path>`,
   and `git diff --cached --name-status` / `git diff --cached`. Source,
   tests and public documentation must remain visible; never hide a broad
   directory merely to make status clean. Run the added-file check in
   [Files that do not belong in the repository](test/README.md#files-that-do-not-belong-in-the-repository)
   and review the public text for private material.
6. On resumption, check running CI and any operation with an uncertain
   outcome before retrying. Follow AGENTS for builds, test-port isolation,
   independent review and merge gates; a checkpoint does not waive them.
   Use the harness of the checked-out branch: do not assume the port-offset
   support on `next` exists on 2.x.
   On macOS, use a Linux container matching the packages in
   [.github/workflows/test.yml](../.github/workflows/test.yml) for the Linux
   suite, sanitizer and callgrind evidence. The root Dockerfile is a runtime
   image, not that test environment.

## Recommended development environment

We use vagrant for development of ngx_mruby.

You may want to develop in same development environment.

### Setup development environment

```
cd ngx_mruby
vagrant up       # run provisioner automatically
vagrant ssh
```

### Test in development environment using ubuntu 18.04

```
cd ngx_mruby/
sh test.sh
```

### Format C source code

Run apply-clang-format script.

```
cd ngx_mruby
sh apply-clang-format
```

## How a handler waits: the record of its fiber

This section describes the code behind `Nginx::Async.sleep`,
`Nginx::Async::HTTP.sub_request` and `Nginx::Stream::Async.sleep`, for a
change to `src/common/ngx_mruby_fiber.c`, `src/http/ngx_http_mruby_async.c`,
`src/stream/ngx_stream_mruby_async.c` or the handlers that call them. What
a script sees is in [Waiting without blocking](concepts/async.md) and in
the reference of [Nginx::Async](class_and_method/README.md#nginxasync-class).

### The record

Each run of a handler runs its code in a new mruby fiber, and allocates a
record for it: from the request pool in HTTP (`ngx_http_mrb_fiber_t`; a
subrequest uses the pool of its main request), and from the connection
pool of the session in stream (`ngx_stream_mrb_fiber_t`). Both begin with
the part that does not depend on the protocol, `ngx_mrb_fiber_t` in
`src/common/ngx_mruby_fiber.h`: the fiber, the `mrb_state`, the slot of the
fiber in the GC root holder (`src/http/ngx_http_mruby_gc_roots.h`), the
state, and one timer event, which each sleep arms again.

- The HTTP record also holds the handler kind, the data of the resume of
  a sleep, the entry of the posted request of the wake, the result that the
  code set, the local URI of `Nginx.redirect`, and the
  `Nginx::Async::HTTP::Response` that `sub_request` returned. The status,
  the headers and the body of the subrequest's response are in the module
  context of the parent request (`sub_response_*`).
- `ctx->fiber_proc` of the module context points at the record of the
  current run. `ctx->wait` (HTTP) and `ctx->sleeping` (stream) point at a
  record that waits for nginx to call its handler again.
- The `RProc` of the code is prepared once, when the code is compiled or
  loaded (`ngx_mrb_fiber_prepare_proc`), not on every run.

The states of a record:

- `RUNNING`: the fiber was created or resumed. It becomes `WAITING` when the
  fiber yields, `DONE` when it returns and `FAILED` when it raises.
- `WAITING`: the code armed a timer or posted a subrequest and yielded. It
  becomes `READY` when the timer fires or the subrequest ends, and
  `CANCELLED` when the owner ends.
- `READY`: the wake marked the record. It becomes `RUNNING` when the handler
  resumes the fiber, and `CANCELLED` when the owner ends.
- `DONE` and `FAILED`: the fiber ended, and its slot is freed. The record
  stays in this state until its pool is freed.
- `CANCELLED`: the owner hook ran while the record was `WAITING` or
  `READY`. The fiber is not resumed, so the rest of its code, an `ensure`
  clause included, does not run.

### Who owns what

- The request or the session owns the record, and the record owns its slot
  and its timer.
- At the first wait of a record, before the wait is armed, the code adds
  the owner hook (a request cleanup in HTTP, which nginx keeps on the main
  request; a connection pool cleanup in stream), allocates the entry of the
  posted request (HTTP), and takes the slot (`ngx_mrb_fiber_hold`). A
  failure raises in the Ruby code with nothing armed. A run that never
  waits takes no slot and adds no cleanup.
- The owner hook calls `ngx_mrb_fiber_cancel`: it deletes a pending timer,
  so that no timer fires on a freed pool, frees the slot (in HTTP also the
  slot of the response of `sub_request`), and marks a `WAITING` or `READY`
  record `CANCELLED`.
- The slot is freed when the fiber ends, normally or with an exception, or
  by the owner hook, once.

### The resume

`ngx_mrb_fiber_resume` starts or resumes the fiber, through
`mrb_protect_error` when another mruby call runs (`mrb->jmp` is set), and
returns whether the fiber waits, returned, or raised. It refuses a record
that is `DONE`, `FAILED` or `CANCELLED` without touching its fiber. When
the fiber raised, it logs the exception once, for its request or session,
and clears `mrb->exc` before it returns, because all requests of the worker
share the `mrb_state`. The callers set the current request or session
for the time the fiber runs: in HTTP `ngx_mrb_run`, `ngx_mrb_post_fiber`
and `ngx_http_mrb_resume_set` with `ngx_mrb_push_request`, in stream
`ngx_stream_mruby_handler` through `ictx->s`. The protocol parts,
`ngx_mrb_run_fiber` and `ngx_stream_mrb_run_fiber`, set `ctx->fiber_proc`
and, in HTTP, the handler kind and the running record
(`ngx_http_mrb_running`), and pass the response of a subrequest as the
value of its `Fiber.yield`.

### HTTP: a wait and its end

- `Nginx::Async.sleep` arms the timer of the record, and
  `Nginx::Async::HTTP.sub_request` posts an in-memory subrequest whose post
  handler is `ngx_mrb_async_http_sub_request_done`; then the code yields.
  Both raise a `RuntimeError` in a log handler or a filter, and
  `sub_request` also in an `mruby_set` handler, because nginx does not wait
  for that subrequest.
- The handler returns `NGX_DONE` and sets the write event handler of the
  request to `ngx_http_mrb_wait_handler`, which ignores events while the
  record is `WAITING` (`ngx_http_mrb_fiber_wait_on_nginx`). A content
  handler first takes a reference to the request (`r->main->count++`),
  because the content checker drops one for each `NGX_DONE`.
- The wake marks the record `READY`. For the timer,
  `ngx_http_mrb_fiber_wake` also posts the request with the entry kept in
  the record and runs the posted requests of the connection. For a
  subrequest, the first call of the post handler copies the response, and
  every call returns nginx's `rc` unchanged, as
  `ngx_http_auth_request_done` does; nginx then wakes the parent.
- `ngx_http_mrb_wait_handler` sees `READY`, sets the write event handler
  back to `ngx_http_core_run_phases` and runs the phases. `r->phase_handler`
  did not move, so the checker calls the same mruby handler, and
  `ngx_http_mrb_fiber_call_again` resumes the fiber instead of starting the
  code. The handler then returns the result of the code to the checker
  through `ngx_mrb_finalize_rputs`, as a handler that did not wait does.
- nginx calling the handler while its record is `WAITING` gets `NGX_DONE`
  again (a content handler takes another reference), and the code does not
  start again. A record that is `CANCELLED` makes the handler return
  `NGX_ERROR`.
- An `mruby_set` handler runs inside the script of the rewrite module, which
  starts the script from its first directive on each call, so nginx does not
  call it again. `ngx_http_mrb_resume_set`, from the wait handler, resumes
  the fiber, assigns the value to the variable, moves `r->phase_handler` to
  the next handler and runs the phases. After an exception, or when the
  variable cannot get the value, it finalizes the request with 500, since
  no phase checker is left to end it: the rewrite module's handler
  returned already.
- A wait that starts in a handler that nginx runs inside another mruby call
  (the location of an internal redirect that an `mruby_set` handler, a log
  handler or a filter makes inside the Ruby call), or after an internal
  redirect replaced the module context of the handler, does not use the
  wake. The timer or the post handler resumes the fiber itself, and
  `ngx_mrb_post_fiber` ends the handler; a content handler there does not
  keep the request, and the handler returns `NGX_AGAIN` while its
  subrequest runs.

### HTTP: the result of a handler and `Nginx.redirect`

- `Nginx.return`, `Nginx.send_header`, `Nginx.status_code=` and
  `Nginx.redirect` with a URL store the result in the record of the fiber
  that runs (`ngx_http_mrb_fiber_set_result`), and an HTTP status also in
  `r->headers_out.status`. `ngx_mrb_finalize_rputs` reads the result of the
  record, so a handler that sets none has no result, whatever an earlier
  handler of the request stored. The exception is a handler whose request
  an internal redirect inside the call sent elsewhere: without a result of
  its own, it returns the status that the target stored.
- `Nginx.redirect` with a local URI, in a post_read, server rewrite,
  rewrite, access or content handler that `ngx_mrb_post_fiber` does not
  resume, keeps the URI in the record (`ngx_http_mrb_fiber_defer_redirect`).
  When the handler has ended, `ngx_mrb_run_request` drops its output, logs
  a line at the `warn` level when the code wrote output or set a status
  after the call, calls `ngx_http_internal_redirect`, drops the reference
  that it took with `ngx_http_finalize_request(r, NGX_DONE)` in every phase
  but content, and returns `NGX_DONE`. The request can be freed in that
  call, so nothing of it is used afterwards. In the other handlers the
  redirect runs inside the call.

### Stream: a wait and its end

- The one mruby handler of a session runs in the access phase.
  `Nginx::Stream::Async.sleep` arms the timer of the record and sets
  `ctx->sleeping`, and the handler returns `NGX_DONE`. While the code
  waits, the read handler of the connection is `ngx_stream_session_handler`:
  on a `listen ... proxy_protocol` it replaces the reader of the PROXY
  header until the code resumes, so that a read event runs the phases.
- The timer marks the record `READY` and runs the phases of the session.
  The access checker calls the handler again, and
  `ngx_stream_mrb_fiber_call_again` resumes the fiber; the handler returns
  `Nginx::Stream::Connection.stream_status`, as a handler that did not wait
  does.
- nginx calling the handler while its record is `WAITING` (a datagram of a
  UDP session, bytes from the client of a TCP session) gets `NGX_DONE`, and
  the code does not start again; the bytes stay for the phase after the
  code. With the event methods that report a read event until the bytes are
  read (`select`, `poll`), the handler deletes the read event until the
  code resumes.
- A `WAITING` record of a connection with `c->close` set (nginx sets it when
  `worker_shutdown_timeout` expires) is cancelled: the handler logs
  `shutdown timeout` at the `info` level and returns `NGX_STREAM_OK`, so the
  session ends.

### What ends a wait from outside

- The client closes the connection. HTTP/1.x: nginx does not read from the
  client while the phases run (`ngx_http_block_reading`), so the wait goes
  on and the code resumes; nginx ends the request when it cannot write the
  response. A TCP stream session: the read event runs the handler, which
  returns `NGX_DONE` without reading, so the wait goes on, and the close is
  seen after the code resumes. A UDP session has no close.
- A reload or SIGQUIT. The old worker finishes the waits of HTTP and of
  stream: their timers are not cancelable, so the worker waits for them.
- `worker_shutdown_timeout` expires. HTTP: nginx terminates the request,
  and its cleanup runs the owner hook, which deletes the timer and cancels
  the record. Stream: the handler cancels the wait and ends the session, as
  above.
- SIGTERM. No hook runs, in HTTP or in stream; `mrb_close` in the cleanup
  of the cycle pool frees the fibers.

No test covers HTTP/2 or HTTP/3 yet: the harness has no client for them.

### Tests and counters

The cases that pin this model are in `test/t/cases/`:
`async_resume_result.rb` (the same end with and without a wait, per
phase), `async_result_isolation.rb` (the result of a handler is its own),
`async_subrequest_return.rb`, `async_set_var.rb`, `redirect_async.rb`,
`stream_async_sleep_udp_once.rb`, `stream_proxy_protocol_wait.rb` and
`workers.rb` (reloads and `worker_shutdown_timeout`). Their configuration
is in `test/conf/conf.d/`, and that of `workers.rb` in `test/conf/workers/`. The soak build
(`-DNGX_MRUBY_DEBUG_STATS`) reports in `Nginx::Debug.stats` the pending
timers of HTTP (`timers`) and of stream (`stream_timers`), the stream
fibers that hold a slot (`stream_fibers`), and the fibers in the GC root
holders (`gc_root_fibers`). `test/soak/soak.rb` keeps `timers` and
`gc_root_fibers` the same from sample to sample, and checks only that
`stream_timers` and `stream_fibers` are reported.

## Adding newer version nginx support

Edit [nginx_version](../nginx_version) and [.travis.yml](../.travis.yml).
See https://github.com/matsumotory/ngx_mruby/commit/02ddb38b68702d9abe8fb0a8c172ee1d80ad2b2d for example.

TODO: retirement policy

## Updating mruby

If you want to update [in-tree mruby](../mruby) to latest version, you can use [update-mruby-subtree](../update-mruby-subtree) script. It adds the mruby upstream repo as dep-mruby and pull all changes to the current branch.

```
git checkout -b BRANCH
sh update-mruby-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
sh update-mruby-subtree REF
```

The script runs `git subtree pull --prefix=mruby --squash dep-mruby REF`, so
the merge starts from the last subtree squash in the history of `mruby/`.
When that squash is old, or when `mruby/` was changed by commits that were
not subtree pulls, the pull stops with conflicts under `mruby/`. Do not
resolve them by hand (files under `mruby/` are never edited by hand).
Instead, inside the merge that stopped, replace the subtree with the exact
tree of the ref, and commit the merge:

```
git rm -r -q --cached mruby
rm -rf mruby
git read-tree --prefix=mruby/ -u REF^{tree}
```

Use the commit id for `REF` here if the tag was not fetched as a local tag;
`update-mruby-subtree` fetches the ref only into `FETCH_HEAD`. `git read-tree`
writes every file of the tree, also the ones that `.gitignore` of this
repository would keep out of a `git add` (for example `mruby/Makefile` and
files under `mruby/lib/mruby/build/`). Before you commit, check that the
index holds the tree of the ref under `mruby/`; the two commands must print
the same id:

```
git write-tree --prefix=mruby/
git rev-parse REF^{tree}
```

Then commit the merge, and put the two ids in the commit message:

```
git commit
```

After the commit, `git rev-parse HEAD:mruby` prints the same id.

The squash commit that `git subtree` made is the second parent of the merge
and records `git-subtree-split: <commit of REF>`, so the next update merges
from that commit instead of the older squash. Commit the merge alone, with
nothing outside `mruby/`, and make the build changes in the commits that
follow.

### Prism

Since mruby 4.1, the mruby compiler is built on
[Prism](https://github.com/ruby/prism), and the tree of mruby has
`mrbgems/mruby-compiler/lib/prism` as a git submodule. The subtree merge
brings only the gitlink of that submodule, so after the merge `mruby/` has
no Prism sources, and the mruby build stops at
`git submodule update --init lib/prism`. Right after the merge commit, run
[vendor-mruby-prism](../vendor-mruby-prism) and commit its result alone:

```
sh vendor-mruby-prism
git commit
```

The script reads the commit of ruby/prism from the gitlink in `HEAD`,
fetches that commit, replaces the gitlink with the files of that commit
that the build of mruby-compiler reads (`src/`, `include/`, `config.yml`,
`templates/template.rb` with the templates of the files that it renders,
and `LICENSE.md`), stages them, and stops unless each staged file is the
same blob as in that commit. Put the commit of ruby/prism in the commit
message. To vendor another commit of ruby/prism, give it as the argument
(`sh vendor-mruby-prism COMMIT`).

At the next `update-mruby-subtree`, this repository has files where the
tree of mruby has the gitlink. When the new ref names the same commit of
ruby/prism, the merge keeps the vendored files. When it names another
commit, the merge changes the gitlink on one side and the vendored files on
the other, and can stop with a conflict at that path. In both cases, finish
the merge with the `git read-tree` steps above, which give `mruby/` the
exact tree of the ref with its gitlink, and then run `vendor-mruby-prism`
again.

`NGX_MRUBY_CORE_GEMS` in [build_config.rb](../build_config.rb) names the mruby
core gems that ngx_mruby builds, so an update does not change them by itself.
The mruby build stops when a listed gem is not in the new `mruby/mrbgems`:
remove it from the list, or replace it, as a decision of its own. To build
anyway while you work on the update, set `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`;
the build then skips the missing gems with a notice. Gems that the new mruby
adds are not built until you add them to the list.

After the update, remove `mruby/build`, build with `sh test.sh`, and commit the
`build_config.rb.lock` that rake wrote with the update: the lock records the
version of mruby. rake writes the lock at the end of a build, and the check of
`NGX_MRUBY_CORE_GEMS` stops the build while rake loads `build_config.rb`, so
rake writes no new lock until every listed gem is found or
`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` is set. A dependency that the new mruby
provides as one of its own gems is no longer cloned, but rake keeps its entry
in the lock, so delete that entry (see "Gem commits" in
[docs/install/README.md](install/README.md)).

## Updating ngx_devel_kit

If you want to update [in-tree ngx_devel_kit](../dependence/ngx_devel_kit) to latest version, you can use [update-devkit-subtree](../update-devkit-subtree) script. It adds the ngx_devel_kit upstream repo as dep-ngx_devel_kit and pull all changes to the current branch.

```
git checkout -b BRANCH
sh update-devkit-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
sh update-devkit-subtree REF
```

## Promoting v3 to master

Until v3 is promoted, `master` is the 2.x line, v3 is developed on `next`, and
`v2.x` is an automatic copy of `master`: on every push to `master`, the
workflow [mirror-v2x.yml](../.github/workflows/mirror-v2x.yml) fast-forwards
`v2.x` to it. The promotion merges `next` into `master` at v3.0.0, so that
`master` becomes the 3.x line and `v2.x` keeps the 2.x line (see
[Branch strategy](../README.md#branch-strategy)). This section is the
procedure.

Agents prepare the pull requests, run the checks and, after the owner's
go-ahead, publish the releases with their tags, as
[AGENTS.md](../AGENTS.md#branches-and-pull-requests) says. The steps below
also give the owner the go for the promotion and the repository settings of
steps 2 and 3; those parts are recommendations (see "Open questions" below).

The repository has four rulesets (as of 2026-10-04). Step 3 changes the first
two:

- `protected-lines`, on `master` and `next`: changes only through pull
  requests, the `ci-ok` check must pass, no deletion, no force push.
- `v2x-mirror`, on `v2.x`: no deletion, no force push. It has no pull request
  rule, because that rule would reject the pushes of the mirror workflow.
- `release-tags`, on `v*` tags: only repository admins create, move or delete
  them.
- `no-branch-shaped-tags`, on the tags `v*.x`, `next`, `master` and `main`:
  nobody can create them, so that a name such as `v2.x` always means the
  branch.

### Conditions

The owner checks that all of these hold and gives the go before step 1:

1. A `v3.0.0-rc.N` pre-release is tagged on `next`, CI passed on it, and no
   defect reported against it blocks the release. How long the last release
   candidate stays out is open (see "Open questions" below).
2. The v3 migration guide and the release notes of v3.0.0 are complete.
3. The last 2.x release before the promotion is tagged on `master`, and the
   entries of its release notes are recorded. 2.x fixes merged after that tag
   go out in the next 2.x release from `v2.x`.
4. The open questions below are decided and recorded, in the v3 plan or in
   this section. Step 4 describes the branches as they are after the
   promotion, and that text depends on what `next` becomes, how fixes travel
   between the lines and which version the site shows.

### Steps

1. **Final merge-up (agent).** Merge `master` into `next` with a pull request,
   as for every merge-up, so that `next` has every 2.x fix. From here until
   step 5, merge nothing else into `master`. If a 2.x fix cannot wait, merge it
   before step 2 and repeat this step.
2. **Stop the mirror (owner).** Check that `v2.x` and `master` point at the
   same commit: `git ls-remote origin refs/heads/master refs/heads/v2.x`
   prints one id twice. If the ids differ, run the workflow on `master`
   (`gh workflow run mirror-v2x.yml --ref master`), wait until the run has
   finished (`gh run list --workflow=mirror-v2x.yml`), and check again. If the
   run fails, its job log says how to repair `v2.x`, for example when `v2.x`
   has commits that are not on `master` or when the push was rejected for the
   `workflows` permission. Do not disable the workflow until the ids match.
   Then disable it with `gh workflow disable mirror-v2x.yml`. From here on,
   `v2.x` stays at the last 2.x commit. Do this before step 5: the merge
   commit of step 5 has the tip of `v2.x` as its first parent, so the
   workflow, if it ran for that push, would fast-forward `v2.x` to 3.x. Step 4
   removes the workflow file from the merge commit of step 5, which also keeps
   it from running; disabling it here protects `v2.x` without relying on
   step 4.
3. **Protect `v2.x` like the other lines (owner).** Add `refs/heads/v2.x` to
   the targets of `protected-lines` and delete `v2x-mirror`. From then on,
   `v2.x` changes only through pull requests that passed `ci-ok`. CI needs no
   change: [test.yml](../.github/workflows/test.yml) already runs on pushes and
   pull requests to `v*.x`.
4. **Prepare `next` (agent).** Two pull requests to `next`, merged in this
   order:
   - A pull request that deletes `.github/workflows/mirror-v2x.yml` and
     describes the branches as they are after the promotion: the branch
     strategy in README.md, the branch table and rules in AGENTS.md, the
     supported versions in SECURITY.md, and "Target branch" in
     `.github/PULL_REQUEST_TEMPLATE.md` (2.x fixes target `v2.x`, v3 fixes
     target `master`). It points the badges of README.md at `master`:
     their images (`branch=next`) and their links
     (`query=branch%3Anext`). It also adds to `.github/dependabot.yml` a
     second `github-actions` entry with `target-branch: "v2.x"`, so that
     the file has it on `master` from step 5 on. Dependabot reads that file
     only from the default branch, and an entry without `target-branch`
     updates only the default branch, so without the new entry nothing would update the
     SHA-pinned actions in the workflows of `v2.x` while 2.x is supported.
     It also moves the site with the lines, so that pages of an unreleased
     3.1 never become the current version (5.2 of
     [the site proposal](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#52-repository-layout)):
     `.github/workflows/site.yml` runs on and deploys from `master` and
     builds `/v2/` from `docs/` of `v2.x`, and `site-v2.yml` and
     `site-dispatch.yml` are removed.
   - The check pull request of
     ["Before the tag"](releases/README.md#before-the-tag) for
     `docs/releases/v3.0.0.md`. As that section says for `next`, its range
     starts at the last `v3.0.0-rc.N` tag, it confirms that the 2.x pull
     requests brought by the merges of `master` into `next` since that tag
     (including step 1) have their entries in the 2.x file, and it copies
     into `v3.0.0.md` the entries of the 2.x release that is not tagged yet
     (the 2.x fixes merged after the last 2.x release of condition 3), because
     v3.0.0 ships them first. After this pull request, merge nothing else into
     `next` until step 5.
5. **Promote (agent, on the owner's go that day).** A pull request with head
   `next` and base `master`, merged with a merge commit when the conditions of
   "Review and merge" in [AGENTS.md](../AGENTS.md#review-and-merge) hold, as
   for every pull request, and only after the owner has given the go-ahead
   that day for the release of step 6 right after it, so that `master` is
   not an untagged 3.x line in between. It has no conflicts, because step 1
   merged `master` into `next`. `master` stays the default branch; nothing about the default
   branch changes. Right before the merge, the owner changes the deployment
   branch rule of the `github-pages` environment from `next` to `master`
   (Settings, Environments, `github-pages`, "Deployment branches"), so that
   the push of the merge deploys the site from `master`.
6. **Tag and release (agent, after the owner's go-ahead), right after step
   5.** Publish the GitHub release `v3.0.0` at the merge commit of step 5
   (`gh release create`, which creates the tag), not marked as a
   pre-release, with the release notes. Releasing at that commit instead
   of the merge commit of the check pull request is the "later commit" case of
   ["Before the tag"](releases/README.md#before-the-tag): the check is
   repeated for the pull requests merged after the check pull request. The
   only one is the promotion of step 5, and it needs no entry: `master` is an
   ancestor of `next` after step 1, so the merge commit of step 5 has the same
   tree as `next` and changes nothing that a configuration, script or build can
   observe.
7. **Announce (agent).** A pull request to `master` that adds the release date
   of v3.0.0 and the end of 2.x support (twelve months later) to README.md and
   SECURITY.md. A pull request to `v2.x` that:
   - describes `v2.x` as the 2.x line in its README.md, AGENTS.md, SECURITY.md
     and pull request template;
   - deletes its copy of `mirror-v2x.yml` (that copy never runs, because only
     pushes to `master` trigger it);
   - points the absolute links to `master` in its files at `v2.x`, because on
     `v2.x` they would lead to the 3.x files: the `tree/master` and
     `blob/master` URLs of this repository (24 on 2026-10-04, in README.md,
     `docs/` and the pull request template), the CI badge
     `badge.svg?branch=master` in README.md and the download link
     `archive/master.zip` in `docs/install/README.md`;
   - adds `-b v2.x` to the clones of the default branch
     (`git clone https://github.com/matsumotory/ngx_mruby.git` without `-b`)
     in `docs/install/README.md`, `Dockerfile` and `misc/provision.sh`.
     Without it, a 2.x user who follows the install guide on `v2.x`, or builds
     the Dockerfile from a `v2.x` checkout, gets 3.x;
   - points its copies of `site-v2.yml` and `site-dispatch.yml`, which run
     only for `master`, at `v2.x`, and makes the dispatch start `site.yml`
     with `--ref master`, so that a change to the 2.x documentation still
     reaches `/v2/`.

   This command lists the links, the badge and the clones:
   `git grep -n -E 'ngx_mruby/(tree|blob|archive)/master|branch=master|clone https://github\.com/matsumotory/ngx_mruby'`.
8. **Afterwards.** 2.x fixes target `v2.x`, and v3 fixes target `master`. Each
   2.x release is published so that it does not become the
   repository's latest release, which stays with 3.x:
   `gh release create <tag> --latest=false`. Through the REST API,
   `make_latest` defaults to `true` for a published release; in the web form,
   leave "Set as latest release" unselected.

### Open questions

The v3 plan does not decide these yet. Each has a recommendation. Condition 4
requires them to be decided before step 1.

- **What `next` becomes after the promotion.** Recommendation: keep it as the
  development branch of the next minor release (3.1), with pre-release tags, so
  that `master` stays the released 3.x line that users of the default branch
  build, as it is the released 2.x line today. The other choice is to retire
  `next` and develop 3.1 on `master`.
- **How long the last release candidate stays out before v3.0.0.**
  Recommendation: at least two weeks without a new report that blocks the
  release.
- **How a fix that both lines need travels after the promotion.**
  Recommendation: fix `master` first and backport the fix to `v2.x` on a
  `backport/v2.x/<topic>` branch, the name AGENTS.md already gives backports.
  Merging `v2.x` into `master` would also bring changes made only for 2.x.
- **Who gives the go for the promotion and changes the repository settings
  in steps 2 and 3.** Recommendation: the owner. Whether condition 1 holds is
  a judgment, the go-ahead for the release of step 6 is the owner's, and
  the settings need admin rights; a mistake there lets `v2.x` move to 3.x.
  AGENTS.md does not cover the go or the repository settings yet.

The site proposal decides which version the site shows after the
promotion (Q1 and Q4, decided by the owner on 2026-10-15, in section 7 of
[`docs/proposals/site.md`](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#7-decisions-2026-10-15)
on `next`). The site, ngx.mruby.org, is built from `docs/` by
`.github/workflows/site.yml` on `next` and deployed by GitHub Actions:
3.x from `next` at the unprefixed paths, and
2.x from `master` under `/v2/`. From the promotion on, the unprefixed
paths show the released 3.x from `master` and `/v2/` shows 2.x from
`v2.x`: steps 4, 5 and 7 move the workflows and the deployment branch
rule.
