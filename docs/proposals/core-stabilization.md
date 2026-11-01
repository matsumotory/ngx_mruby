# Proposal: core stabilization: one lifecycle for the fiber of a handler, and one end of the request

Status: accepted, 2026-11-01. The owner decided Q1 to Q6 of section 9 on
2026-11-01, in a session's question, each as recommended (the chosen options
are quoted in section 9). Implementation follows the order of section 8; the
first pull request is step 1 (tests only). Written on 2026-11-01 from
`next` at `a654a37f6`, `master` at `6eae5a2df`, and the source of nginx 1.31.8 (the version in
`nginx_version`). The owner chose on 2026-11-01, in a session's question, to
extend the test harness first and then to go on to the core stabilization,
the rework of the lifetime of fibers and of the end of the response (the row
on step 4 under "Queue" in [docs/HANDOFF.md](../HANDOFF.md) quotes the
option); [#706](https://github.com/matsumotory/ngx_mruby/pull/706) made the
extension. This proposal is the design for the rows of step 4 of section 6 of
[the v3 plan](v3-plan.md) on the fiber lifecycle, the response finalization,
the common layer and the execution context, as far as they decide how a
handler that waits ends. It changes no code. Line numbers are those of the
commits above; statements marked "unverified" come from reading the code and
were not run.

Not in this proposal: the Pillar B rows on headers and on `Nginx::Var`, the
two agent proxy rows of step 4 (log handlers before `access_log`, and
`mruby_variable`), the table-driven directives and the filter handler
pointers. They do not depend on the model below, except that the record of
section 4.1 lives in the per-request and per-session context that the
execution-context row introduces.

## 1. Why this part of the core

ngx_mruby published six security advisories in 2026. Four of them sit where
state outlives what owns it, or where a request or a response ends:

- [GHSA-86wx-fcwx-m3vh](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-86wx-fcwx-m3vh):
  the timer of `Nginx::Stream::Async.sleep` outlived its stream session
  (fixed in 2.7.3 by #645).
- [GHSA-22jc-w698-vfqw](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-22jc-w698-vfqw):
  an upstream peer of the worker pointed at memory of the request pool or the
  connection pool that set it (fixed in 2.7.2).
- [GHSA-h7fw-wf49-8rv5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-h7fw-wf49-8rv5),
  items 1, 6, 7 and 9: request and session pointers used outside their
  request or session, an exception after output that let the request go on,
  and handlers that waited for the request body (fixed in 2.7.1).
- [GHSA-8mxf-gvvp-38fq](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-8mxf-gvvp-38fq):
  a HEAD request received a body from a handler that wrote output (fixed in
  2.7.2).

The other two,
[GHSA-gxqc-3p4h-5p36](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-gxqc-3p4h-5p36)
and
[GHSA-8r78-rxqq-5gp5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-8r78-rxqq-5gp5),
are about strings with a NUL byte.

Each fix was made where its defect was. Today the three paths that wait
(the HTTP sleep, the HTTP subrequest and the stream sleep) each have their
own code for when the fiber is kept from the GC, how it is resumed, when it
is released, and who ends the request or the session after it. Section 2
describes that code, and section 4 proposes one model for all three.

## 2. What the code does today

### 2.1 Every handler

- Each run of a handler runs its code in a new fiber: `ngx_mrb_run` and
  `ngx_mrb_run_request` (`src/http/ngx_http_mruby_module.c:784-796`,
  `903-1240`) call `ngx_mrb_start_fiber` (`src/http/ngx_http_mruby_async.c:138-185`);
  in stream, `ngx_stream_mruby_handler` (`src/stream/ngx_stream_mruby_module.c:729-784`)
  calls `ngx_stream_mrb_start_fiber` (`src/stream/ngx_stream_mruby_async.c:86-135`).
- `ngx_mrb_run_fiber` sets `ctx->handler_kind` for the time the fiber runs,
  and `Nginx::Async` raises a `RuntimeError` in the handlers that nginx cannot
  resume: log handlers and output filters (`src/http/ngx_http_mruby_async.c:69-121`,
  since 2.7.1, #551). A direct `Fiber.yield` there ends the handler with 500
  (`:240-251`).
- The fiber is kept in a record of the request pool (`ngx_mrb_fiber_t`,
  `src/http/ngx_http_mruby_async.c:53-67`) or of the connection pool
  (`ngx_stream_mrb_fiber_t`, `src/stream/ngx_stream_mruby_async.c:25-41`),
  with a slot in the GC root holder of its `mrb_state`
  (`src/http/ngx_http_mruby_gc_roots.h`, #682). HTTP takes the slot and adds a
  pool cleanup when the fiber is created, for every handler, also one that
  never waits (`src/http/ngx_http_mruby_async.c:154-182`). Stream takes the
  slot when the fiber first sleeps (`src/stream/ngx_stream_mruby_async.c:291-299`,
  #645 and #698), but allocates its record and adds a pool cleanup for every
  run, also one that never sleeps (`:110-121`). Both free the slot when the fiber ends
  (`src/http/ngx_http_mruby_async.c:231-258`,
  `src/stream/ngx_stream_mruby_async.c:67-81`) or in the pool cleanup.
- The compiled `RProc` of the handler is changed on every run (`upper` and
  `e.target_class`, through `mruby/internal.h`;
  `src/http/ngx_http_mruby_async.c:150-152`,
  `src/stream/ngx_stream_mruby_async.c:123-125`).
- The result of a handler is kept in `r->headers_out.status`.
  `Nginx.return`, `Nginx.status_code=` and `Nginx.send_header` store the
  value there (`ngx_mrb_send_header`, `src/http/ngx_http_mruby_core.c:360-392`),
  also a negative one such as `Nginx::DECLINED`, which wraps around, and
  `ngx_mrb_finalize_rputs` returns a stored value of 100 or more as the result
  of a handler without output (`src/http/ngx_http_mruby_core.c:264-278`). A
  value that an earlier handler stored is therefore the result of a later
  handler of the same request that stores none. The server rewrite handler
  of the main test server stores `Nginx::DECLINED` for every request
  (`test/conf/nginx.conf:573`), so the later handlers of that server that set
  no result return `NGX_DECLINED` (unverified: this is why `/sleep_with_proxy`
  and `/sleep_with_proxy_set_code` reach `proxy_pass`, see 2.3).

### 2.2 HTTP: how a handler starts to wait

- `Nginx::Async.sleep` is `__sleep` followed by `Fiber.yield`, and
  `Nginx::Async::HTTP.sub_request` is `__sub_request` followed by
  `Fiber.yield` (`mrbgems/ngx_mruby_mrblib/mrblib/mrb_nginx.rb:100-120`).
- `__sleep` (`src/http/ngx_http_mruby_async.c:385-435`) allocates from the
  request pool, for each call, an `ngx_event_t` with the data of the resume,
  arms the timer and adds a request cleanup that deletes it. A handler that
  sleeps N times keeps N events and N cleanups until the request ends.
- `__sub_request` (`:518-591`) posts an in-memory subrequest whose post
  handler resumes the fiber. The response is kept in the module context of
  the request, one per request, and `Nginx::Async::HTTP.last_response` builds
  the Ruby object from it (`:593-620`).
- What the handler returns to nginx while it waits
  (`src/http/ngx_http_mruby_module.c:1064-1104`), and what nginx's phase
  checker does with it (nginx `src/http/ngx_http_core_module.c`):

| Handler | Checker | Returned while waiting | What the checker does |
|---|---|---|---|
| post_read | generic (`:916-949`) | `NGX_DONE` (sleep), `NGX_AGAIN` (subrequest) | returns; the request stays |
| server_rewrite, rewrite | rewrite (`:953-976`) | `NGX_DONE`, `NGX_AGAIN` | `NGX_DONE`: returns. `NGX_AGAIN`: `ngx_http_finalize_request(r, NGX_AGAIN)`, which leaves the request to the posted subrequest and sets `ngx_http_writer` as its write event handler |
| access | access (`:1119-1192`) | `NGX_DONE`, `NGX_AGAIN` | returns |
| content (a phase handler, not `r->content_handler`) | content (`:1302-1332`) | `NGX_DONE` after `r->main->count++` and `ngx_http_request_empty_handler` as the write event handler (sleep, #646); `NGX_AGAIN` (subrequest) | `ngx_http_finalize_request(r, rc)`, which for `NGX_DONE` drops the reference that the handler took |
| `mruby_set` | none: it runs inside the script of the rewrite module (NDK) | `NGX_DONE`, `NGX_AGAIN` | NDK records `NGX_DONE` as the status of the script and runs the rest of the script; it ignores `NGX_AGAIN` (`dependence/ngx_devel_kit/src/ndk_set_var.c:44-81`) |

### 2.3 HTTP: how a wait ends

- The timer: `ngx_mrb_timer_handler` (`src/http/ngx_http_mruby_async.c:338-370`)
  calls `ngx_mrb_post_fiber` (`:263-336`). It restores the status of the
  request from the time of the sleep, resumes the fiber, logs an exception
  and clears `mrb->exc` (the result is then 500), assigns the result of an
  `mruby_set` handler to its variable, and calls `ngx_mrb_finalize_rputs`.
  Then: `NGX_DECLINED` moves to the next phase handler and runs the phases;
  `NGX_DONE` means that the fiber waits again; any other value goes to
  `ngx_http_finalize_request(r, rc)`, followed by
  `ngx_http_run_posted_requests`. Before that, it sets `headers_out.status`
  to 500 for every result but `NGX_OK`, `NGX_DECLINED` included (`:327-329`),
  one more stored status for the later handlers of the request (2.1); the
  upstream of `/sleep_with_proxy` overwrites it.
- This replaces nginx's phase checker for the result after the wait, and it
  handles the result as the content checker would, not as the checker of the
  handler's phase would. Without a stored status (2.1):
  - an access handler that sets no result returns `NGX_OK` when it does not
    wait (`src/http/ngx_http_mruby_core.c:277`), on which the access checker
    goes on with the next access handler under `satisfy all`, and allows the
    request and skips the other access handlers under `satisfy any` (nginx
    `src/http/ngx_http_core_module.c:1146-1165`); after a sleep it ends the
    request without a response (unverified). With
    `satisfy any`, a 401 or 403 after a sleep ends the request instead of
    trying the next access handler (unverified);
  - a post_read handler that sets no result goes on with the next phase when
    it does not wait, and ends the request without a response after a sleep
    (unverified);
  - an `mruby_set` handler that sleeps gets its variable assigned, and then
    the request ends without a response (unverified);
  - a rewrite handler that sets no result ends the request without a
    response with or without a sleep: the queue row on it in
    [docs/HANDOFF.md](../HANDOFF.md) and decision (b) of 2026-10-04 (section
    3).
- The subrequest: nginx calls the post handler
  `ngx_mrb_async_http_sub_request_done` (`src/http/ngx_http_mruby_async.c:469-516`)
  inside `ngx_http_finalize_request` of the subrequest (nginx
  `src/http/ngx_http_request.c:2771-2773`). It resumes the parent's fiber
  there, runs the parent's phases from there for `NGX_DECLINED`, finalizes
  the parent for results other than `NGX_DECLINED` and `NGX_OK`, and returns
  the parent's result to the finalization of the subrequest (`NGX_DONE` when
  the parent waits again). The end of the subrequest and the end of the
  parent's handler run as one call.
- In a content handler that has slept, `sub_request` raises a `RuntimeError`
  since 2.7.3 (`:534-542`), because nothing would finalize the request after
  the subrequest (entry 2 of [the 2.7.3 release notes](../releases/v2.7.3.md)).
  The content handler's write event handler ignores events while it waits,
  and nginx would run that handler when the subrequest ends.
- `Nginx::Async::HTTP.sub_request` in an `mruby_set` handler does not make
  nginx wait: the request goes on while the subrequest runs, and an
  exception after it leaves the client without a response
  ([docs/class_and_method/README.md](../class_and_method/README.md#nginxrputsstring),
  under `Nginx.rputs`).

### 2.4 HTTP: `Nginx.redirect` with a local URI

`Nginx.redirect` calls `ngx_http_internal_redirect` inside the Ruby call
(`src/http/ngx_http_mruby_core.c:585`). nginx runs the phases of the target
location right there, and its mruby handlers run in fibers of their own
inside the fiber of the calling handler (`mrb->jmp` is set). Since 2.7.3 an
exception of such a handler stops at that handler (`mrb_protect_error`,
`src/http/ngx_http_mruby_async.c:212-228`, entry 3 of the 2.7.3 notes), and a
content handler there that sleeps does not keep the request
(`src/http/ngx_http_mruby_module.c:1093-1097`). `ngx_http_internal_redirect`
takes a reference to the request and returns `NGX_DONE` (nginx
`src/http/ngx_http_core_module.c:2666-2670`); `Nginx.redirect` drops the
return value, and the calling handler goes on after the call and returns its
own result. Two handlers can then answer one request. The three queue rows
on `Nginx.redirect` in [docs/HANDOFF.md](../HANDOFF.md) are the cases found
so far:

- a rewrite handler of the target sleeps while the calling handler answers:
  the output of the sleeping handler follows the response when its timer
  fires;
- a content handler of the target ends the request at
  `Nginx::Async.sleep`, without its output;
- a content handler that sleeps and then calls `Nginx.redirect`: the client
  gets 200 and the body of the target, and the access log has 500.

### 2.5 Stream

- One mruby handler, in the access phase (`ngx_stream_mruby_init`,
  `src/stream/ngx_stream_mruby_module.c:787-805`), whose result is
  `Nginx::Stream::Connection.stream_status` (`:783`).
- A session has one timer, `ctx->sleep` (`src/stream/ngx_stream_mruby_core.h:18-24`),
  which `__sleep` arms (`src/stream/ngx_stream_mruby_async.c:263-310`); the
  data of the resume is allocated for each call. The connection pool cleanup
  of each fiber cancels the pending timer and frees the slot
  (`:237-261`, #645).
- After the sleep, `ngx_stream_mrb_timer_handler` and
  `ngx_stream_mrb_post_fiber` (`:137-227`) handle the result as nginx's
  generic checker would (#651, entry 4 of the 2.7.3 notes): a copy of the
  checker's table (nginx `src/stream/ngx_stream_core_module.c:191-227`).
- nginx calls the handler again while it waits when the session gets a read
  event. A UDP session gets one for each datagram from its client, through
  the read handler `ngx_stream_session_handler`, which runs the phases
  (nginx `src/stream/ngx_stream_handler.c:181`, `288-297`). The handler then
  starts its code again in a second fiber while the first is suspended
  (`test/t/cases/stream_async_sleep_udp_reuse.rb`; #698 keeps that second
  fiber from the GC). A TCP session gets no read event during the access
  phase, because nginx does not watch its read side then, except with
  `listen ... proxy_protocol`, whose read handler can still be armed
  (nginx `src/stream/ngx_stream_handler.c:188-197`; unverified).
- When `worker_shutdown_timeout` expires, nginx sets `c->close` and calls the
  read handler of every connection (nginx `src/core/ngx_cycle.c:1455-1484`).
  `ngx_stream_mruby_handler` does not look at `c->close`. No test covers a
  stream session that waits when the timeout expires.

### 2.6 Reload and worker exit

- A graceful stop (a reload for the old workers, or SIGQUIT) closes the
  listening sockets and the idle connections, and the worker exits once no
  timer that is not cancelable is left (nginx
  `src/os/unix/ngx_process_cycle.c:740-770`, `ngx_event_no_timers_left`). The
  timers of `Nginx::Async.sleep` and `Nginx::Stream::Async.sleep` are not
  cancelable, so an old worker finishes the sleeps in flight and their
  requests and sessions end as usual: `test/t/cases/workers.rb` checks it
  (#706).
- With `worker_shutdown_timeout`, an HTTP request that waits is terminated
  (nginx `src/http/ngx_http_request.c:2657-2660`), which runs its request
  cleanups (`:2949-2958`): the timer is deleted and the fiber is not resumed.
  Stream: see 2.5.
- A fast stop (SIGTERM) runs the `exit_process` hooks, among them
  `mruby_exit_worker`, and destroys the cycle pool (nginx
  `src/os/unix/ngx_process_cycle.c:974-1031`), whose cleanup closes the
  `mrb_state` (`src/http/ngx_http_mruby_module.c:316-325`,
  `src/stream/ngx_stream_mruby_module.c:143-152`). The pools of open requests
  and sessions are not destroyed, so no fiber cleanup runs after `mrb_close`.

### 2.7 The known gaps

From the queue of [docs/HANDOFF.md](../HANDOFF.md) and from the reading
above:

1. A rewrite handler that ends without `Nginx.return` sends no response
   (the queue row; decision (b) of 2026-10-04 for `next`).
2. After a wait, access, post_read and `mruby_set` handlers end in another
   way than without the wait (2.3, unverified).
3. A result that an earlier handler stored in `r->headers_out.status` is the
   result of a later handler that stores none (2.1).
4. `sub_request` after a sleep raises in a content handler (2.3); the queue
   has the sessions' proposal to support it.
5. The parent's handler is resumed inside the finalization of its
   subrequest (2.3); decision (c) puts the rewrite of how resumed handlers
   end, which includes this, into the core stabilization.
6. The three cases of `Nginx.redirect` (2.4).
7. `sub_request` in an `mruby_set` handler does not make nginx wait (2.3).
8. A request that sleeps N times keeps N timers and N cleanups (2.2).
9. A UDP datagram that arrives while the handler waits runs the code again
   in another fiber (2.5).
10. A stream session that waits when `worker_shutdown_timeout` expires is
    not tested (2.5).
11. The `RProc` is changed on every run, an HTTP handler that never waits
    still takes a slot, and a handler of either protocol that never waits
    still allocates a record and adds a pool cleanup (2.1).
12. `mrb->exc` is cleared in several places on the resume paths
    (`src/http/ngx_http_mruby_async.c:293-299`,
    `src/stream/ngx_stream_mruby_async.c:158-167`), not on every exit path
    of one function (the Pillar B row asks for that).

## 3. What binds the design

The owner decided the design principles on 2026-10-04 ("Design principles"
in [AGENTS.md](../../AGENTS.md)): one `mrb_state` per worker, shared by the
requests of that worker; no blocking; keep the existing performance;
measure performance regularly. For this proposal they mean:

- The record of a waiting handler belongs to its request or session and to
  that pool. Nothing per request goes into state that the requests share,
  except the slot of the GC root holder, which exists today.
- A handler waits only through nginx: a timer, a subrequest, and later the
  socket API of part (d) of step 7. The model adds no other wait.
- A handler that does not wait gets no allocation and no call that it does
  not have today; a wait allocates once per record, not once per sleep.
- Every implementation pull request is compared in the perf lane
  (section 7).

The decisions that bind it, all on `next`:

- The owner's answer of 2026-10-04 to the analysis of `Nginx::Async`,
  「全部推奨通りでいこう、安全網から始めて」 ("go with all the recommendations,
  starting from the safety net"): (a) `Nginx::Async.sleep` in a content
  handler is supported; (b) a rewrite handler that ends with no output and no
  `Nginx.return` goes on to the next phase on `next`, as with
  `NGX_DECLINED`; (c) amended on 2026-10-29: the rewrite of how resumed
  handlers end lands on `next`, in the core stabilization of 3.0.0 (item 15
  of section 7 of the plan). [docs/HANDOFF.md](../HANDOFF.md), "Decisions",
  records (a) and (b) until their work writes them in the plan.
- Item 15 of section 7 of the plan: the content handler of a subrequest that
  returns `Nginx::HTTP_OK` without output keeps answering 500, so that
  `auth_request` fails closed.
- Item 8 of section 7 accepts five behavior changes of v3, each listed in
  the migration guide: exceptions outside the phase, 500 after an exception
  that follows `rputs`, the exact match of `Headers#delete`, the empty 200,
  and a body with any status. #574 made the empty 200: a content handler of
  the main request that ends without output answers 200 with an empty body.
  The other behavior changes of section 5 are not covered by item 8: each is
  a defect fix, follows from a decision above, or is a question of section
  9.

## 4. The proposed model

In one sentence: a handler that waits keeps one record, owned by its request
or session, and the end of the wait does not end the handler itself but
wakes nginx, whose phase checker calls the handler again, which resumes the
fiber and returns the result to that checker as if it had not waited.

### 4.1 The record

One record per run of a handler that may wait, allocated from the pool of
its owner: the main request's pool (subrequests share it) or the connection
pool of the stream session. It holds:

- the fiber, the `mrb_state` and the slot of the GC root holder;
- the state (4.2) and, for HTTP, the handler kind;
- the owner: the request (`ngx_http_request_t *`) or the session;
- one timer event, armed again for each sleep;
- for a subrequest, its status, headers and body;
- the result of the run (4.6).

The part that does not depend on the protocol (the states, the slot, the
timer, the resume, the clearing of `mrb->exc`) is the common layer of the
plan's row, in new files `src/common/ngx_mruby_fiber.c` and `.h` (the name is
a proposal), built for both modules through `config.in`. The protocol parts
are the owner hook, the wake (4.4), the mapping of the result to the
phase's return value, and the current request or session that the Ruby API
reads.

With the recommendations of section 9, each request (each
`ngx_http_request_t`: a subrequest and its parent can wait at the same time,
`test/t/cases/async_exception_state.rb:77`) has at most one record that waits
at a time (the phases run one handler at a time, and `Nginx.redirect` no
longer runs a target inside its caller, Q2), and a stream session has one
(Q4). The record is then allocated once per request from its pool and
reused by the later handlers of the request. The module context points at
it, but the owner hook and the timer reach it through their own pointers,
because `ngx_mrb_finalize_rputs` drops the module context after it sent
output (`src/http/ngx_http_mruby_core.c:303`) and an internal redirect clears
every module context. If Q2 or Q4 is answered the other way, there is one
record per run, as today, and with Q2 answered no, a content handler that
waits inside `Nginx.redirect` still does not keep the request (2.4).

### 4.2 States

| State | Entered when | Left when |
|---|---|---|
| `RUNNING` | the handler starts the fiber, or resumes it | the fiber yields (`WAITING`), returns (`DONE`) or raises (`FAILED`) |
| `WAITING` | `Nginx::Async.sleep` or `sub_request` armed the wait, and the fiber yielded | the timer fires or the subrequest ends (`READY`), or the owner ends (`CANCELLED`) |
| `READY` | the wake (4.4) | the checker calls the handler, which resumes the fiber (`RUNNING`), or the owner ends (`CANCELLED`) |
| `DONE`, `FAILED` | the fiber ended; the slot is freed then | the record is reused by the next handler of the request, or freed with the pool |
| `CANCELLED` | the owner hook ran while the fiber was `WAITING` or `READY`; the timer is deleted and the slot freed | never; the fiber is not resumed. nginx no longer calls the handler of a terminated or freed request; a handler that finds its record `CANCELLED` returns `NGX_ERROR` |

A cancelled fiber is dropped without running the rest of its code, so an
`ensure` clause after the wait does not run. This is so today as well; Q3
asks whether 3.0.0 keeps it.

### 4.3 Who owns what

- The owner owns the record; the record owns the slot and the timer.
- The owner hook is added once, at the first wait of the record: for HTTP a
  request cleanup of the main request (`ngx_http_cleanup_add`, nginx
  `src/http/ngx_http_core_module.c:2751`), which nginx runs when it
  terminates the request and in `ngx_http_free_request`, before the pool is
  destroyed (nginx `src/http/ngx_http_request.c:2949-2958`, `3999-4006`); for
  stream a cleanup of the connection pool, as #645 added. It deletes the
  timer if it is set, frees the slot if it is held, and sets `CANCELLED` if
  the fiber waits. A timer that fires therefore always finds its owner, and
  a subrequest's post handler is called by nginx only while both requests
  exist.
- The slot is taken at the first wait, as the stream path does since #645,
  instead of when the fiber is created; until then the fiber is the running
  fiber or in the GC arena of the call. A handler that never waits then
  takes no slot and adds no cleanup, in HTTP and in stream (gap 11). The GC stress build of
  `test.sh` (`-DMRB_GC_STRESS`) runs every case with this; the perf lane
  shows what it saves (section 7). If the GC stress runs or a sanitizer show
  a fiber collected before its first wait, the slot stays at creation.
- Every allocation of a wait is made and checked before the wait is armed,
  so a refused or failed call leaves nothing armed.
- The `RProc` is prepared once, when the code is compiled or loaded, with
  the macros of `mruby/proc.h` (`MRB_PROC_SET_TARGET_CLASS`) where they
  suffice, instead of on every run (gap 11).

### 4.4 How a wait starts, and how it ends

A wait starts:

- In every HTTP phase, the handler returns `NGX_DONE` while it waits, also
  for a subrequest (today `NGX_AGAIN`), because the rewrite checker
  finalizes the request on `NGX_AGAIN` and sets `ngx_http_writer` as its
  write event handler (2.2). A content handler takes a reference to the
  request first, as today; it does so for each `NGX_DONE`, because the
  content checker drops one for each.
- The handler sets the request's write event handler to a wait handler of
  ngx_mruby that ignores events until the record is `READY`, as
  `ngx_http_limit_req_module` does while it delays a request (nginx
  `src/http/modules/ngx_http_limit_req_module.c:323`, `333-359`).
- A stream handler returns `NGX_DONE`; the generic checker returns.

A wait ends with a wake, and the wake only marks the record and gives the
owner back to nginx:

- The timer: the record becomes `READY`. HTTP, for a phase handler
  (`mruby_set` is the exception below): the timer handler posts the request
  with a posted-request entry kept in the record (`ngx_http_post_request`
  allocates one from the pool for each call without it, nginx
  `src/http/ngx_http_request.c:2726-2731`) and runs the posted requests of
  its connection, so that nginx calls the request's write event handler, as for
  any request that is not the active one of its connection. Stream: it runs
  the phases of the session (`ngx_stream_core_run_phases`), as today.
- The subrequest: its post handler copies the status, the headers and the
  body into the record at its first call, sets `READY`, and returns nginx's
  `rc` unchanged, as `ngx_http_auth_request_done` does (nginx
  `src/http/modules/ngx_http_auth_request_module.c:223-234`). nginx calls
  the post handler on each `ngx_http_finalize_request` of the subrequest
  that is not `NGX_DONE` or `NGX_DECLINED` (`src/http/ngx_http_request.c:2771-2773`):
  again with the result of `ngx_http_special_response_handler` after an
  `rc` of 300 or more (`:2788-2812`), and again when a buffered or postponed
  subrequest is finalized later (`:2817-2824`). The record keeps what the
  first call saw, the status and headers of the subrequest's response and
  the body that it had in memory then, as the code does today, whose first
  call resumes the parent (`test/t/ngx_mruby.rb:787-793`,
  `/async_http_sub_request_notfound`, pins it); the later calls change
  nothing and return `rc`. A call for a record that is `CANCELLED` does
  nothing either. nginx then wakes the parent itself (`src/http/ngx_http_request.c:2876-2885`, "http
  wake parent request").
- The wait handler sees `READY`, sets `ngx_http_core_run_phases` as the write
  event handler again and runs the phases.

The checker of the phase calls the same mruby handler again, since
`r->phase_handler` (`s->phase_handler`) did not move. The handler finds its
record `READY`, resumes the fiber instead of starting one, and returns the
result of the code to the checker. This is how `auth_request` waits for its
subrequest: its post handler marks the context done, and the phase handler
returns the stored result when nginx calls it again (nginx
`src/http/modules/ngx_http_auth_request_module.c:102-128`).

What this gives, for the phase handlers (`mruby_set` is the exception
below):

- ngx_mruby calls neither `ngx_http_finalize_request` nor
  `ngx_stream_finalize_session` after a wait, and the copies of the
  checkers' tables in `ngx_mrb_post_fiber`, `ngx_mrb_timer_handler`,
  `ngx_mrb_async_http_sub_request_done` and `ngx_stream_mrb_timer_handler`
  go away. The checker ends the request or the session once, with the
  result of the handler, in the same way with or without a wait (gaps 2
  and 5).
- The parent's handler is resumed in the parent's own run of the phases,
  after the subrequest has ended (gap 5).
- A content handler can wait for a subrequest, before or after a sleep, since
  nothing but the checker finalizes the request (gap 4; Q1).

When nginx calls the handler while its record is `WAITING` (an event that
the wait handler did not catch, or a UDP datagram, 2.5), the handler returns
`NGX_DONE` again (a content handler after taking another reference) and does
not start its code (gap 9; Q4). When the record is `WAITING` and the
connection has `c->close` set (`worker_shutdown_timeout`, 2.5), a stream
handler cancels the wait, logs `shutdown timeout` at the `info` level and
ends the session with `NGX_STREAM_OK`, as `ngx_stream_proxy_module` does
(nginx `src/stream/ngx_stream_proxy_module.c:1752-1755`); an HTTP request
never gets there, because nginx terminates it (2.6).

`mruby_set` is the exception. Its handler runs inside the script of the
rewrite module, whose handler starts the script from its first directive
each time nginx calls it (nginx `src/http/modules/ngx_http_rewrite_module.c:137-183`),
so a second call would run the directives before the `mruby_set` again, and
a `rewrite` without a flag would rewrite the URI twice. The wake of an
`mruby_set` record therefore does not run the phases at the same index: the
record is marked as one of `mruby_set`, and the wait handler of the request
resumes the fiber itself.

- When the code returns, the wait handler assigns the value to the
  variable, moves `r->phase_handler` to the next handler of the rewrite
  phase and runs the phases, as on the main test server today. The
  directives of the same script after the `mruby_set` ran before the sleep,
  without the value (NDK, 2.2).
- A status that the code sets with `Nginx.return` does not end the handler:
  without a wait, an `mruby_set` handler ends with its value alone
  (`src/http/ngx_http_mruby_module.c:1139-1166`), and the model makes the
  end after the sleep the same. Today a status after the sleep ends the
  request with that status (2.3; item 9 of section 5).
- An exception after the sleep answers 500, as today and as
  [docs/class_and_method/README.md](../class_and_method/README.md#nginxrputsstring)
  documents: the wait handler calls `ngx_http_finalize_request(r,
  NGX_HTTP_INTERNAL_SERVER_ERROR)`. This is the one place where ngx_mruby
  ends a request after a wait, because no phase checker is left to do it:
  the rewrite module's handler returned already.

The documentation says all of this. `sub_request` there: Q5.

### 4.5 The resume

One function of the common layer resumes a record. It sets the current
request or session and the handler kind for the time the fiber runs,
resumes the fiber (through `mrb_protect_error` when another mruby call runs,
as today), and returns one of three outcomes: the fiber waits again, it
returned a value, or it raised. When it raised, the function logs the
exception once, for its own request or session, and clears `mrb->exc`
before it returns, on every path (gap 12). The protocol part maps the
outcome to the phase's return value: HTTP through `ngx_mrb_finalize_rputs`
for the handler kind; stream through `stream_status`.

### 4.6 One end of the response

- The result of a run is kept in the record. `Nginx.return`,
  `Nginx.status_code=` and `Nginx.send_header` store an HTTP status in
  `r->headers_out.status` and in the record, and a return code below 0
  (`Nginx::DECLINED`, `Nginx::DONE` and the like) only in the record. A
  handler that stores nothing has no result, whatever an earlier handler
  stored (gap 3). The Pillar B row lists this as a candidate, not a
  decision: Q6.
- A run without a result ends as follows, with or without a wait:
  rewrite handlers go on with the next phase handler, as with
  `NGX_DECLINED` (decision (b), gap 1), and server rewrite handlers the same
  way if the owner extends (b) to them (Q6); access and post_read handlers
  return `NGX_OK`, as they do today without a wait
  (`src/http/ngx_http_mruby_core.c:277`): the access checker then goes on
  with the next access handler under `satisfy all` and allows the request
  under `satisfy any`, and the generic checker goes on with the next phase.
  The model keeps `NGX_OK` because it only makes the end after a wait the
  same as without it; changing what an access handler without a result
  means is not proposed; a content handler of the main request answers 200 with an
  empty body (#574); a content handler of a subrequest ends the subrequest,
  whose parent answers (and `Nginx::HTTP_OK` without output there stays 500,
  item 15).
- A run with output, a status or an exception ends as it does today without
  a wait (#574, #594, 2.7.1).

### 4.7 Subrequests

- The record keeps the response, and `sub_request` returns it: the resume
  passes the `Nginx::Async::HTTP::Response` to the fiber, so `Fiber.yield`
  in `sub_request` returns it. `last_response` returns the same object, as
  the Pillar B row says.
- Several subrequests at once, and subrequests with a method, a body and
  headers, stay after v3.0.0 (the plan's row on them).

### 4.8 `Nginx.redirect`

Recommended in Q2: `Nginx.redirect` with a local URI records the URI, and the
handler goes on to its end; output and a status that it sets after the call
are not sent, and a line at the `warn` level says so. When the handler ends,
ngx_mruby calls `ngx_http_internal_redirect`, drops the reference that it
took with `ngx_http_finalize_request(r, NGX_DONE)` where the checker does not
do it (every phase but content), and returns `NGX_DONE`. That call is the
handler's last use of the request, its context and the record, since the
request can be freed in it. The target
location's handlers then run outside the caller's fiber, as for nginx's own
internal redirects, and can wait like any handler; one handler answers the
request (gap 6). `Nginx.redirect` with a URL (`http://`, `https://`,
`$scheme`) stays as it is: it sets `Location` and the status.

### 4.9 What happens when

| Event | HTTP | Stream |
|---|---|---|
| The client closes the connection during a wait | HTTP/1.x: nginx does not read the client during the phases (`ngx_http_block_reading`), so the wait goes on; the response then fails to be written, and nginx ends the request. The model keeps this (Q3). HTTP/2: a `RST_STREAM` closes the stream and terminates its request, and the owner hook runs (unverified) | TCP: nginx does not watch the read side during the access phase (except with `proxy_protocol`, 2.5); as HTTP/1.x. UDP: no close |
| A timeout | No timer of nginx runs during a sleep, and the model adds none; a subrequest ends by its own timeouts (for example `proxy_read_timeout`), and the parent resumes with its status | As HTTP for the sleep |
| A reload or SIGQUIT | The old worker finishes the waits (their timers are not cancelable), as `test/t/cases/workers.rb` checks | The same |
| `worker_shutdown_timeout` expires | nginx terminates the request; the owner hook deletes the timer and drops the fiber | The handler cancels the wait and ends the session (4.4) |
| SIGTERM | No hook runs; `mrb_close` frees the fibers (2.6) | The same |
| A second datagram of a UDP session while the code waits | n/a | The handler returns `NGX_DONE` and does not run the code again (Q4) |

## 5. What changes for users of 2.x

Each item below is a difference that a configuration or a script of 2.x can
observe; the pull request that makes it adds its entry under "Behavior
changes: read before upgrading" in `docs/releases/v3.0.0.md` and `.ja.md`,
with every line of the template. "Before" is 2.7.3 and `next` at
`a654a37f6`.

1. An access or post_read handler that waits and then ends without a result.
   Before: the request ends without a response (unverified, 2.3). Now: nginx
   goes on as when the handler does not wait. Under `satisfy any` that
   means that the request is allowed and the other access handlers are
   skipped: a script that sleeps and then ends without a result to deny
   must return `Nginx::HTTP_FORBIDDEN` (the entry says so under "Affected"
   and "What to do"). With `satisfy any`, a 401 or 403 after a wait lets
   nginx try the next access handler. A defect fix (gap 2).
2. A rewrite handler that ends without a result, with or without a wait
   (and, with Q6, a server rewrite handler). Before: no response. Now: the
   next phase handler runs. Decision (b); the queue row on it.
3. With Q6: a handler that sets no result after an earlier handler of the
   request called `Nginx.return Nginx::DECLINED` (or another value). Before:
   the later handler returns that value; on a server whose server rewrite
   handler returns `Nginx::DECLINED`, a content handler without output goes
   on to the next content handler or the static module. Now: it has no
   result (4.6), and that content handler answers the empty 200 of #574.
4. `Nginx::Async::HTTP.sub_request` returns the response (additive; "New
   features").
5. If Q1 is answered yes: `sub_request` works in a content handler, also
   after `Nginx::Async.sleep`. Before: it raises a `RuntimeError` after a
   sleep (2.7.3), and is not documented for content handlers. A new feature,
   with an entry for the removed `RuntimeError`.
6. If Q2 is answered as recommended: output and a status that a handler sets
   after `Nginx.redirect` with a local URI are not sent, the target's
   handlers run after the calling handler ends instead of inside the call,
   and a content handler of the target that sleeps answers after its sleep.
   This changes the cases of `Nginx.redirect` in
   `test/t/cases/async_sleep_in_content.rb`,
   `test/t/cases/async_exception_state.rb` and
   `test/t/cases/redirect_to_raising_handler.rb` that pin the order (section
   6); their expectations change only with the owner's answer.
7. If Q4 is answered as recommended: a UDP datagram that arrives while the
   stream code waits does not run the code again.
8. If Q5 is answered as recommended: `sub_request` in an `mruby_set` handler
   raises a `RuntimeError`.
9. An `mruby_set` handler that sets a status with `Nginx.return` after a
   sleep. Before: the request ends with that status (unverified, 2.3). Now:
   the status does not end the handler, as without a sleep (4.4).
10. A stream session that waits when `worker_shutdown_timeout` expires ends
    then, with `shutdown timeout` at the `info` level.
11. Not a behavior change, for "Fixes": a request that sleeps N times no
    longer keeps N timers and N cleanups; the `RProc` is no longer changed
    on every run.

The behavior that 2.x promised and that stays: the entries 2, 3 and 4 of
[the 2.7.3 release notes](../releases/v2.7.3.md) (a content handler answers
after its sleep, an exception in a redirect target stops at its handler, a
stream session goes on or ends after a sleep by its result), their Fixes on
#645 and #698 (no timer on a freed pool, each fiber kept from the GC), the
500 after an exception that follows output (2.7.1), and the `RuntimeError` of
`Nginx::Async` in log handlers and output filters (2.7.1).

## 6. The tests that pin the model

The cases that exist and must pass unchanged (except those that items 5
and 6 of section 5 name, which change only with the owner's answers to Q1
and Q2):

- `test/t/cases/async_sleep_in_content.rb`: a content handler that sleeps
  answers with its body, with the status it returns, with 500 without its
  output after an exception, after two sleeps, on a kept-alive connection
  and for the next request on it; a subrequest to such a handler gets its
  output; no fiber is left in the GC root; `Nginx.redirect` to a sleeping
  content handler and then a status (Q2); `sub_request` after a sleep raises
  (Q1).
- `test/t/cases/async_exception_state.rb`: an exception after a sleep or a
  subrequest answers 500 to that request only; an exception after output in
  a resumed handler answers 500 without that output; an exception or a
  status after `Nginx.redirect` in a resumed handler (Q2); a subrequest to a
  location whose handler sleeps.
- `test/t/cases/async_set_var_target.rb`: a later async handler does not
  assign its result to the variable of `mruby_set`.
- `test/t/cases/async_sleep_in_log.rb` and
  `test/t/cases/async_sleep_in_output_filter.rb`: `Nginx::Async` raises in log
  handlers and filters, and `Fiber.yield` there ends the handler with an
  error line or 500.
- `test/t/cases/async_subrequest_raise.rb`: a subrequest that raises leaves
  no fiber in the GC root, also through `rewrite ... last`.
- `test/t/cases/redirect_to_raising_handler.rb`: an exception in the target
  of `Nginx.redirect` answers 500 and closes the connection, and the code
  after the call runs (Q2).
- The `Nginx::Async` cases of `test/t/ngx_mruby.rb` (`/async_sleep`,
  `/async_sleep_loop`, the `sub_request` locations, `/sleep_with_proxy`,
  `/sleep_with_proxy_set_code`) and its `Nginx::Stream::Async.sleep` case on
  12352.
- `test/t/cases/stream_async_sleep_result.rb` (the result after a sleep),
  `test/t/cases/stream_async_sleep_teardown.rb` (a reset during the sleep),
  `test/t/cases/stream_async_sleep_udp_reuse.rb` (the second datagram gets
  the reply).
- `test/t/cases/workers.rb`: each worker has its own `mrb_state`, and the old
  workers finish an HTTP and a stream sleep in flight across a reload.

The cases to add, each in a fragment and a case file of its own on a server
without server-level handlers, so that no stored status hides a result (2.1):

- `async_resume_result.rb`: for post_read, server rewrite, rewrite, access
  (with `satisfy all` and with `satisfy any`) and content handlers, pairs of
  locations whose handlers end in the same way, one without a wait and one
  after `Nginx::Async.sleep 1`: without a result, with `Nginx::DECLINED`,
  with `Nginx::OK`, with 403, with output, with an exception. Each pair
  asserts the same status, body and next request on the connection. The same
  for a subrequest wait in rewrite handlers. This is the case that
  shows "the same end with or without a wait".
- `async_result_isolation.rb`: a server rewrite handler that calls
  `Nginx.return Nginx::DECLINED` and a later handler that sets nothing; the
  later handler's own result decides (item 3 of section 5, with Q6).
- `async_sleep_many.rb`: a handler that sleeps 1,000 times for 1 ms answers,
  and `Nginx::Debug.stats` shows the same `timers` and `gc_root_fibers`
  before and after. It guards against a regression and holds today as well,
  since `timers` counts the timers still pending; the pool size is not
  visible to a test, so the fix of gap 8 (item 11 of section 5) is measured
  by the soak lane (section 7).
- `async_subrequest_return.rb`: `sub_request` returns the response, equal to
  `last_response`; with Q1, a content handler waits for a subrequest before
  and after a sleep, answers with its body, and the next request on the
  connection is answered, with no `[alert]` line in `error.log`.
- `redirect_async.rb` (Q2): one case for each of the three cases of 2.4,
  asserting the one response and the status of the access log line.
- `async_set_var.rb`: on a server without server-level handlers, an
  `mruby_set` handler that sleeps sets the variable that `proxy_pass` uses;
  with Q5, `sub_request` there raises and the request gets 500.
- `stream_async_sleep_udp_reuse.rb`, extended (Q4): the code runs once for
  the session (one log line of the code for two datagrams), and the reply
  arrives after the first datagram's sleep.
- `workers.rb`, extended: a reload with `worker_shutdown_timeout 1s` while an
  HTTP and a stream handler wait longer; the old workers exit after the
  timeout, the stream code does not run twice, and the stop leaves no error,
  no sanitizer report and no leak.
- The bugs of gap 2 come as the two commits of AGENTS.md "Writing tests":
  the test commit fails on the base, the fix commit passes.

Each pull request runs the suite under ASan and UBSan and under valgrind
(the cells of the `build` matrix that a code change runs), and quotes the
results (section 8 of the plan).

## 7. Measurement

- The perf lane compares each implementation pull request with its base.
  Every default scenario must stay `ok`: `hello`, `headers`, `var`,
  `filter`, `sleep`, `sub_request`, `file`, `proxy_plain_2k`,
  `proxy_plain_64k`, `proxy_stream_plain_50`, `responses_stream_plain_50`,
  `auth`, `route_json_2k`, `ruby_call_1` and `ruby_call_10`
  (`test/perf/perf.rb`, `DEFAULT_SCENARIOS`). `sleep` and `sub_request` (a
  rewrite handler that waits) are the rows that the wake and the second call
  of the handler change; the other rows change only through the slot at the
  first wait and the `RProc` prepared once, which should lower them. A
  `WARN` or `FAIL` goes to the owner as AGENTS.md says.
- The lane has no stream scenario, so a change to `src/stream/` alone states
  what it adds per session, as AGENTS.md asks.
- The soak lane (`test/soak/soak.rb`) keeps `gc_live`, `gc_root`,
  `gc_root_fibers`, `gc_arena_idx`, `timers`, `fd_own` and `active` the same
  from sample to sample, and bounds `VmRSS`, for the `sleep`, `sub_request`
  and `disconnect` scenarios (the client closes during the sleep). The pull
  request of the common layer counts the stream timers and fibers in
  `Nginx::Debug.stats` as well, for a stream scenario added with it.

## 8. The order of the implementation pull requests

Each is small, on `next`, with its tests and its release notes entry, and
each bug fix comes as a test commit and a fix commit.

1. Tests only: `async_resume_result.rb` and `async_result_isolation.rb` with
   the cases that pass today, so that the later pull requests show what
   they change.
2. The common layer with no change of behavior: the record shared by HTTP
   and stream, one timer per record, the resume function that clears
   `mrb->exc` on every path, the `RProc` prepared once, the slot at the
   first wait, and the stream counters of `Nginx::Debug.stats`. The perf
   lane shows its cost.
3. HTTP: the wake and the second call of the handler for the timer, with
   the result handled by nginx's checkers (gap 2, two commits), and the
   result kept in the record (gap 3, with Q6).
4. Decision (b): a rewrite handler without a result goes on (gap 1), and
   with Q6 a server rewrite handler.
5. HTTP subrequests through the wake (gap 5), `sub_request` returns the
   response, and with Q1 the content handler waits for a subrequest (gap 4).
6. Stream: the wake and the second call of the handler, with Q4 (gap 9)
   and the end on `c->close` (gap 10).
7. `Nginx.redirect` with Q2 (gap 6).
8. `mruby_set` with Q5 (gap 7).

Steps 3 to 8 depend on 2; 4 to 8 do not depend on each other, except that 5
and 7 touch the same code of the content handler and go one after the
other. Parts (a) and (c) of step 7 of the plan (the shared dictionary and
the upstream peer hook) do not touch this code; part (d), the socket API,
waits on the record as one more kind of wait.

## 9. Questions for the owner

Q1. Does 3.0.0 support `Nginx::Async::HTTP.sub_request` in a content
handler, also after `Nginx::Async.sleep`? Recommendation: yes. With the
model, nothing but nginx's checker ends the request after the subrequest,
which is why 2.7.3 raises there; a content handler that answers from a
subrequest then works like one in a rewrite handler, the plan's row on
`sub_request` after v3.0.0 (calls from a handler to a key service or a
ledger) builds on it, and the sessions' proposal in the queue asks for it. The
cost is the cases of `async_subrequest_return.rb`.
Decided 2026-11-01: yes (the owner chose 「動くようにする (推奨)」).

Q2. Does `Nginx.redirect` with a local URI take effect when the handler ends
(4.8), instead of running the target inside the call? Recommendation: yes.
One handler then answers each request, which removes the three cases of 2.4
and the nested run of mruby handlers inside another fiber, and a redirect
target can wait like any other location. The cost: code that answers after
`Nginx.redirect` is no longer sent (a `warn` line says so), and the existing
cases of section 6 that pin the order change their expectations, which
needs this answer.
Decided 2026-11-01: yes (the owner chose 「handler の終わりで効く (推奨)」).

Q3. Does a handler that waits keep running when its client closes the
connection, and is a fiber whose request ends during a wait dropped without
running its `ensure` clauses, as today? Recommendation: yes for 3.0.0, and
document both. nginx does not read the client of an HTTP/1.x request during
the phases. Noticing the close costs no allocation: `ngx_http_test_reading`
as the read event handler while the request waits, as
`ngx_http_limit_req_module` sets it while it delays (nginx
`src/http/modules/ngx_http_limit_req_module.c:322`), and the close would then
terminate the request and run the owner hook. But it would end a script
halfway when its client goes away, for example before the script records
what the request cost, which no handler of 2.x sees. Resuming a fiber with
an exception from a cleanup, so that `ensure` runs, would run Ruby code
while nginx frees the request.
Decided 2026-11-01: yes for 3.0.0, both documented (the owner chose 「いまの動きを保つ (推奨)」).

Q4. Does a UDP stream session run its code once, so that a datagram that
arrives while the code waits does not start it again? Recommendation: yes.
nginx gives the datagram to the handler only during that call, so it is not
proxied or answered; today it runs the code a second time in a second fiber
of the same session while the first is suspended, which is the path of
GHSA-86wx-fcwx-m3vh and of #698.
Decided 2026-11-01: yes (the owner chose 「1回にする (推奨)」).

Q5. Does `Nginx::Async::HTTP.sub_request` in an `mruby_set` handler raise a
`RuntimeError` in 3.0.0, while `Nginx::Async.sleep` there keeps working as
described in 4.4? Recommendation: yes. nginx does not wait for that
subrequest, the request goes on without the variable, and an exception after
it leaves the client without a response (2.3); a raise tells the script at
once, as in log handlers since 2.7.1.
Decided 2026-11-01: yes (the owner chose 「RuntimeError にする (推奨)」).

Q6. Is the result of a handler its own, so that a handler that sets nothing
does not return the value that an earlier handler of the request stored
with `Nginx.return` (4.6), and does a server rewrite handler that ends
without a result go on to the next phase handler like a rewrite handler
(decision (b) names rewrite handlers)? Recommendation: yes to both. The
Pillar B row on finalization lists "make `Nginx.return` type-independent of
`headers_out.status`" as a candidate, and item 8 of the plan does not cover
it. Today a server rewrite handler that returns `Nginx::DECLINED`, as the
main test server's does, makes every later handler without a result return
`NGX_DECLINED`, so what a script's handler does depends on handlers that it
does not contain, and the same script behaves differently on two servers.
For server rewrite handlers, the reason of (b) holds: an end without a
response helps no script. The cost: a configuration with such a server
rewrite handler and content handlers without output changes (item 3 of
section 5), with its entry.
Decided 2026-11-01: yes to both (the owner chose 「handler ごとにする (推奨)」).

Not a question: how a handler ends without `Nginx.return` after a wait. The
model ends it as without the wait (4.6), which decision (b), #574 and item 15
already decide, with Q6 for server rewrite handlers.

## 10. Risks

- The second call of the handler depends on `r->phase_handler` not moving
  during the wait. A module that changes it, or that replaces the write
  event handler while a request waits, would break the wake. nginx's own
  modules do not do that during the phases; the cases of section 6 with
  `proxy_pass` and `rewrite ... last` check it, and a case with
  `auth_request` after a waiting access handler is added with step 3 of
  section 8.
- HTTP/2 and HTTP/3 deliver write events to the request through their own
  code, and the harness has no HTTP/2 or HTTP/3 client yet (the queue row on
  the harness). The wait handler ignores events until `READY`, but no test
  shows it on those protocols until the clients exist.
- Taking the slot at the first wait relies on the running fiber and the GC
  arena keeping a new fiber alive until then. The GC stress build checks it;
  if it fails, the slot stays at creation (4.3).
- The behavior changes of section 5 reach code that relied on the old
  order or on a stored status. Each has its entry and its line in the
  migration guide.
- The perf lane measures the HTTP paths only. A stream change is described
  per session until the lane has a stream scenario.

## 11. Security review

The security session reviews this proposal before the first implementation
pull request, and each implementation pull request before it is merged:
the owner wants the same eyes on this code that found the advisories of
section 1. A finding goes to the process of [SECURITY.md](../../SECURITY.md),
not into a pull request or this file.
