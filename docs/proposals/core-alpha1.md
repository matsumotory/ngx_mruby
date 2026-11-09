# Proposal: the rest of the v3 core before `v3.0.0-alpha.1`

Status: in progress. The five design decisions of section 5 were made on
2026-11-09, and no point of the design is open. Next step: the pull
requests of section 4 that wait for nothing start, first "Log handlers
before `access_log`" and "`mruby_variable`", by 2026-11-16.

This proposal designs what is left of step 4 of section 6 of
[the v3 plan](v3-plan.md): the work that has to be on `next` before
`v3.0.0-alpha.1` is tagged. The plan says to tag it "when the v2 suite
passes under the new core with sanitizers clean". The fiber of a handler
and how a request ends after a wait were designed in
[the core stabilization proposal](archive/core-stabilization.md),
implemented by #712 to #735 and are described in
[How a handler waits](../DEVELOPMENT.md#how-a-handler-waits-the-record-of-its-fiber).
What is left has had no design. The items are those of the row of step 4
under "Queue" in `docs/HANDOFF.md` and of the row there on the rest of the
async resume rewrite:

- the Pillar B rows of the plan on the execution-context type, on headers,
  on `Nginx::Var`, on the filter handler pointers and on the table-driven
  directive definitions (section 2);
- the common layer for HTTP and stream beyond the fiber: code loading,
  upstream switching, error logging and the duplicate directive check
  (section 2);
- a wait that starts in a handler that nginx runs inside another mruby
  call, which is still ended by `ngx_mrb_post_fiber` (section 2.9);
- the two agent proxy rows that item 15 of section 7 of the plan puts into
  alpha.1: mruby log handlers run before `access_log`, and the directive
  `mruby_variable` (sections 2.10 and 2.11);
- the part of the Pillar B row on response finalization that is left, a
  body with any status (section 2.12).

The proposal changes no code. It was written on 2026-11-09 from `next` at
`ec8efde7c` and nginx 1.31.8 (the version in `nginx_version`). Line numbers
are those of that commit. Statements marked "unverified" come from reading
the code and were not run.

Not in this proposal: the renaming of request and response accessors (the
last Pillar B row). It is additive and not needed for alpha.1.

## 1. What each item changes, in short

| Item | Section | What a script, a configuration or a build sees |
|---|---|---|
| One execution context, and the phases of the Ruby API | 2.1 | A method called in a handler where it has no effect raises (item 8 of section 7 of the plan accepted this); a per-request store is added |
| Headers | 2.2 | `delete` removes exactly the named headers; `Content-Type`, `Content-Length`, `Location` and `Date` set through `headers_out` reach nginx's own fields; a name that is not a String raises |
| One setter for `Nginx::Var` | 2.3 | Assigning a variable that nginx does not know raises `NameError`, and one that nginx does not let scripts change raises `RuntimeError` |
| Filter handlers | 2.4 | A filter set at `http` or `server` level runs in the locations below it |
| Directive table and one duplicate check | 2.5 | `nginx -t` refuses a stream hook given twice in one context, as it refuses an HTTP one |
| Common code loading | 2.6 | Nothing |
| Common upstream switching | 2.7 | Nothing |
| Common error logging | 2.8 | Stream logs the backtrace of an exception in a build with `--with-debug`, as HTTP does |
| Waits inside another mruby call | 2.9 | `Nginx.redirect` with a local URI raises in `mruby_set` handlers and filters; #770 makes it raise in log handlers |
| Log handlers before `access_log` | 2.10 | `access_log` writes the variables that mruby log handlers set; the status it writes is the one sent |
| `mruby_variable` | 2.11 | A new directive |
| A body with any status | 2.12 | Output followed by `Nginx.return` with a status of 201 or from 300 up is sent with that status, instead of nginx's own page, and `error_page` does not apply to it |

## 2. The items

Each item has: what the code does today, what is wrong with it, the
design, whether it changes behavior (and so needs an entry under "Behavior
changes: read before upgrading" in `docs/releases/v3.0.0.md` and
`docs/releases/v3.0.0.ja.md`), the test that fails before the change, which
callgrind scenarios of the perf lane it is expected to move, and what it
really depends on.

### 2.1 One execution context, and the phases of the Ruby API

**Today.** A Ruby method finds what it acts on in four ways:

- The request: a process-wide pointer, `ngx_mruby_request`
  (`src/http/ngx_http_mruby_request.c:77`), set by `ngx_mrb_push_request`
  (`:88-92`) and read by `ngx_mrb_get_request_or_raise` (`:105-112`), which
  raises only when no request is set. The pointer is set and restored by
  `ngx_mrb_run` (`src/http/ngx_http_mruby_module.c:785-797`), by
  `ngx_mrb_run_cycle` (`:745-749`), around the SSL handshake handler
  (`:2533-2542`), and by the resume paths
  (`src/http/ngx_http_mruby_async.c:438-447`, `:496`, `:562-598`). 35 lines
  of `src/http` read it, some of them in macros that define several
  methods.
- The kind of handler: `ctx->handler_kind` in the module context
  (`src/http/ngx_http_mruby_core.h:80`), set while a fiber runs
  (`src/http/ngx_http_mruby_async.c:336-361`), and the record of the
  running fiber, `ngx_http_mrb_running` (`:115`). Only `Nginx::Async`
  (`:161-174`), `Nginx.redirect` (`:717-751`) and `Nginx.send_header`
  (`src/http/ngx_http_mruby_core.c:451-452`) consult them.
- The SSL handshake and the server context code: `mrb->ud` points at the
  server configuration while the code runs
  (`src/http/ngx_http_mruby_module.c:1561-1565`, `:2608-2613`), read by
  `ngx_mrb_ssl_get_srv_conf` (`src/http/ngx_http_mruby_ssl.c:18-27`) and by
  `Nginx::Server#add_listener` (`src/http/ngx_http_mruby_server.c:30-45`).
- Stream: `mrb->ud` points at `ngx_stream_mruby_internal_ctx_t`
  (`src/stream/ngx_stream_mruby_module.h:19-25`), whose `s` is the session
  while its code runs (`src/stream/ngx_stream_mruby_module.c:757`), read by
  `ngx_stream_mrb_get_session_or_raise`
  (`src/stream/ngx_stream_mruby_core.c:20-28`).

**What is wrong.** A method checks that a request or a session exists, not
whether the handler that runs can use the method. A script that sets
`headers_out` in a log handler, or calls `Nginx.rputs` in a header filter,
gets no error, and its call has no effect (the comment at
`src/http/ngx_http_mruby_module.c:1265-1273` describes the output of a
header filter that is lost). Item 8 of section 7 of the plan accepted that
such calls raise in v3. The same question is answered in three places with
three mechanisms, so a new API has no single place to say where it works.

**Design.**

- One type in `src/common/ngx_mruby_exec.h`, for HTTP and stream:

  ```c
  typedef struct ngx_mrb_exec_s {
    ngx_mrb_exec_kind_t kind;     /* what runs: see below */
    void *on;                     /* ngx_http_request_t *, ngx_stream_session_t *,
                                     ngx_connection_t * (SSL), ngx_conf_t * or NULL */
    void *srv_conf;               /* SSL handshake and server context code */
    void *record;                 /* the fiber record of a handler, or NULL */
    ngx_log_t *log;               /* where Nginx.log writes */
    struct ngx_mrb_exec_s *prev;  /* the context that ran before this one */
  } ngx_mrb_exec_t;
  ```

  The kinds are those of `ngx_http_mruby_handler_kind_t`
  (`src/http/ngx_http_mruby_core.h:42-53`) plus the configuration code
  (`mruby_init`, the server context code), the worker hooks, the SSL
  handshake and the stream handler.
- Each `mrb_state` has one small structure, reached through `mrb->ud`,
  that holds the current context. Every place that runs Ruby code pushes a
  context that lives on its C stack, and puts back the previous one when
  the code returns or yields. A fiber that a timer or a subrequest resumes
  gets a new context from its record. `ngx_mruby_request`, the uses of
  `mrb->ud` above, `ctx->handler_kind` and `ngx_http_mrb_running` are
  replaced by it. Because the pointer belongs to the state, the two states
  that exist during a reload each have their own.
- Every Ruby method gets its context through one function,
  `ngx_mrb_exec_require(mrb, allowed, name)`, where `allowed` is a mask of
  kinds. Outside them it raises `RuntimeError` with a message that names
  the method and the handler, as `Nginx::Async` does since 2.7.1.
- Where each group of methods works:

  | Methods | Where they work | New raise |
  |---|---|---|
  | Reading the request: `Nginx::Request` getters, `headers_in[]`, `Nginx::Var` reads, `Nginx::Connection`, `Nginx::Server` getters | every HTTP request handler and filter | none (outside a request they raise today) |
  | Changing the request: `uri=`, `args=`, `method=`, `request_line=`, `headers_in[]=` and `delete` | `mruby_set`, post_read, server rewrite, rewrite, access and content handlers | log handlers, header and body filters |
  | Assigning variables: `Nginx::Var#name=`, `#set` | every HTTP request handler and filter (log handlers need it, see 2.10) | none |
  | The response head: `headers_out[]=` and `delete`, `Nginx.status_code=`, `Nginx.return` and `Nginx.send_header` with a status, `content_type=` | every HTTP request handler and filter, while nginx has not sent the response header (`r->header_sent`) | after the header is sent, log handlers included |
  | Output: `Nginx.rputs`, `Nginx.echo` | post_read, server rewrite, rewrite, access and content handlers | `mruby_set` handlers, log handlers, header filters |
  | The body of a body filter: `Nginx::Filter#body`, `#body=`, `#output` | body filters | everywhere else |
  | `Nginx.redirect` with a local URI | post_read, server rewrite, rewrite, access and content handlers | `mruby_set` handlers, log handlers, header and body filters (decision 1, section 2.9) |
  | `Nginx::Async` | as today (`src/http/ngx_http_mruby_async.c:124-138`) | none |
  | `Nginx::SSL` | the SSL handshake handler | none (it raises outside today) |
  | `Nginx::Server#add_listener` | the server context code | none (it raises outside today) |
  | `Nginx.log`, constants, `Nginx.module_name` and the other methods that need no request | everywhere | none |

  The pull request writes the mask of each method from this table and
  documents it in `docs/class_and_method/README.md`. A method that the
  table leaves out keeps working where it works today.
- A per-request store (additive): `Nginx::Request#store` returns a Hash
  that is the same object in every handler of the request, created at the
  first call and kept in a slot of the GC root holder
  (`src/http/ngx_http_mruby_gc_roots.h`). The store belongs to the request,
  not to the module context, and survives internal redirects (decision 2):
  a cleanup of the request pool holds the slot and the request it belongs
  to, and frees the slot when the pool is destroyed. The module context
  caches the pointer; after an internal redirect cleared the module
  context, the first call walks the cleanups of the request pool once to
  find the store again. A subrequest shares the pool of its main request,
  so the cleanup records the request, and a subrequest gets a store of its
  own. A request that never calls the method allocates nothing. The agent
  proxy uses it to carry the key and the budget decision of its
  authentication handler to its log handler, also after `error_page 529 =
  @name` sends the request to another provider. The method may be renamed
  in review.

**Behavior change.** Yes: the "New raise" column, with one entry in the
release notes that lists the table. The store is a "New features" entry.

**Test that fails first.** For the store, `test/t/cases/request_store.rb`:
an access handler stores a value, `error_page 404 = @next` sends the
request to a named location whose content handler answers the stored
value, and a subrequest sees its own empty store; today the method does
not exist. For the phases, `test/t/cases/api_phases.rb` with a location for
each handler kind that calls one method of each row and asserts the
`RuntimeError` line in `error.log` and the response (for example, a log
handler that sets `headers_out` leaves the response as it was, and its
`error.log` line names `headers_out[]=` and "a log handler"). Today no call
raises.

**Perf.** Each method reads the context through `mrb->ud` and tests a mask,
where today it reads one global: a few instructions per call. Each run of a
handler pushes and pops one context, which replaces the save and restore of
`ngx_mruby_request` and of `handler_kind`. The scenarios with the most
method calls per request are `headers`, `var` and `auth`; the expected
change is below 1% instructions per request without the GC, and the pull
request measures it.

**Depends on.** Nothing. It edits the lookup in every method, so it does
not run at the same time as the pull requests of 2.2 and 2.3 (section 4).

### 2.2 Headers

**Today.**

- `Headers_in#delete` and `Headers_out#delete` call
  `ngx_mrb_del_request_header` (`src/http/ngx_http_mruby_request.c:294-425`),
  which compares the first `len` bytes of each name (`:329`) and stops at
  the first match. `delete("X-Foo")` removes the first of `X-Foo` and
  `X-Foo-Bar`, whichever comes first, and leaves the other `X-Foo` lines.
- `[]=` (`:449-494`) removes the old values with a loop of
  `ngx_mrb_get_request_header` (exact name, `:176-177`) and
  `ngx_mrb_del_request_header` (prefix), so it also removes headers whose
  name starts with the name.
- Of the headers that nginx keeps in fields of `r->headers_out`, only
  `Server` is set there (`:270-284`). `headers_out["Content-Type"] = ...`
  adds a list entry while `r->headers_out.content_type` keeps its value, so
  nginx can send two `Content-Type` lines (unverified), and
  `headers_out["Content-Length"]` does not change `content_length_n`.
- `[]=` does not check the type of the name, or of a value that is neither
  an Array nor nil (`:455`, `:481`).

**Design.**

- `delete(name)` removes every header whose name has the same length and
  the same bytes ignoring case, and no other. `[]=` uses the same match.
- For `Headers_out`, a table of the headers that nginx keeps in fields:
  `Content-Type` sets `r->headers_out.content_type` (and clears the charset
  and the lowercase copy) and adds no list entry; `Content-Length` sets
  `content_length_n` from a decimal value (anything else raises
  `ArgumentError`) and clears `r->headers_out.content_length`; `Location`,
  `Date` and `Server` add the list entry and point the field at it, as
  nginx's `ngx_http_headers_filter_module` does for the headers it sets.
  Reading one of them returns the field; deleting one clears the field and
  removes the entry.
- The name is a String or a Symbol, or `[]=` and `delete` raise
  `TypeError`. A value is a String, nil (delete), an Array (one header per
  element), or an object whose `to_s` returns a String, converted as
  `Nginx::Var` converts values (`ngx_mrb_var_to_string`,
  `src/http/ngx_http_mruby_var.h:49-56`); a `to_s` that fails raises.

**Behavior change.** Yes, three entries: the exact match of `delete` and
`[]=` (accepted in item 8 of the plan), the four headers that now reach
nginx's fields, and the `TypeError` for a name.

**Test that fails first.** `test/t/cases/headers_exact.rb`: a request with
`X-Foo: 1`, `X-Foo-Bar: 2` and `X-Foo: 3`, a handler that calls
`headers_in.delete("X-Foo")` and answers with the remaining names (today
`X-Foo-Bar` disappears and one `X-Foo` stays); a handler that sets
`headers_out["Content-Type"]` and a response with exactly one
`Content-Type`; `headers_out["X-N"] = 1` answers `X-N: 1`;
`headers_out[1] = "x"` answers 500 with `TypeError` in `error.log`.

**Perf.** `headers` sets two response headers: one lookup of the name in
the table of four fields per set (a switch on the length). Expected below
0.5%.

**Depends on.** Nothing.

### 2.3 One setter for `Nginx::Var`

**Today.** Two functions assign a variable: `ngx_mrb_var_set_vector`
(`src/http/ngx_http_mruby_var.c:102-180`), used by `Nginx::Var#name=`
through `method_missing` and the accessors that #610 defines
(`:193-263`, `:373-390`), and by the end of `mruby_set`
(`src/http/ngx_http_mruby_async.c:467`, `:583`); and
`ngx_mrb_var_set_func` (`src/http/ngx_http_mruby_var.c:419-517`) for
`Nginx::Var#set`. They are copies of each other with small differences in
how the name is converted and lowercased. Both log at the error level and
return nil when nginx does not know the variable or does not let it be
changed (`:143-173`, `:484-514`).

**Design.** One function, `ngx_mrb_var_assign(mrb, r, name, len, value)`,
that converts the value (`ngx_mrb_var_to_string`), looks the lowercased
name up once, and does what `ngx_http_script_set_var_code` does for the
`set` directive. `#set`, `#name=` and the end of `mruby_set` call it.
A name that nginx does not know raises `NameError`, and a variable that
nginx does not let scripts change (such as `$uri`) raises `RuntimeError`
(decision 3). The message names the variable.

When such an error shows. The worker does not stop: the exception goes to
the handler, and a handler that does not rescue it ends as after any
exception, so its request answers 500 (a log handler only logs it) and
`error.log` has the exception. `nginx -t` cannot find these errors,
because the name of the variable is decided by Ruby code that runs per
request. What stops nginx when the configuration is read is a syntax
error in handler code (the code is compiled then, and `nginx -t` fails)
and a wrong `mruby_variable` declaration (section 2.11). A misspelled
variable name in an assignment, or an assignment to a variable that nginx
does not let scripts change, shows at the first request that runs the
assignment, as that request's 500 and its `error.log` line.

**Behavior change.** Yes, one entry: an assignment that logged an error
line and returned nil now raises.

**Test that fails first.** `test/t/cases/var_assign.rb`, where
`v.no_such_var = "x"` answers 500 with `NameError` in `error.log`, and
`v.set("uri", "x")` answers 500 with `RuntimeError`; today both return nil
and the request goes on. The same file runs the other assignments through
`#set` and `#name=` and compares the results.

**Perf.** `auth` assigns three variables. The shared function does the
same work as either copy; no change is expected.

**Depends on.** Nothing.

### 2.4 Filter handlers: their type, their merge, and phase handlers only where used

**Today.**

- `header_filter_handler` is declared as `ngx_http_handler_pt`
  (`src/http/ngx_http_mruby_module.h:119`), which takes one argument, holds
  `ngx_http_mruby_header_filter_handler` and its inline variant, which take
  two (`src/http/ngx_http_mruby_module.c:2177`, `:2191`), and is called with
  one (`:2245`).
- `ngx_http_mruby_merge_loc_conf` (`:538-567`) merges the code of the
  filters but not `header_filter_handler` and `body_filter_handler`, which
  the directives set (`:1784-1861`). A filter given at `http` or `server`
  level has its code in each location but no handler there, so it runs
  only for requests that match no location (`:2215`, `:2264`).
- `ngx_http_mruby_handler_init` (`:640-723`) adds twelve phase handlers,
  the file and the inline handler of six phases, whatever the
  configuration holds. Each request calls those of the phases it passes,
  and each returns `NGX_DECLINED` when its location has no code.

**Design.**

- The header filter handler gets a type with one argument, and its two
  functions take one argument.
- The merge copies a handler pointer together with its code, so a location
  without a filter of its own runs the filter of its server or of `http`.
- The directive functions record in the main configuration which phase and
  which form (file, inline) a directive uses anywhere; `mruby_add_handler`
  counts as the file form of the content phase. Postconfiguration adds only
  those handlers.

**Behavior change.** Yes, one entry: a filter set at `http` or `server`
level now runs in the locations below it (the Pillar B row names this).

**Test that fails first.** `test/t/cases/filter_inherit.rb`: an
`mruby_output_header_filter_code` at `server` level that adds a header, and
a request to a location of that server without a filter; the header is
missing today.

**Perf.** Every scenario of a configuration that leaves out some phases
calls fewer handlers: `nginx.agent.conf` of the soak lane uses no
post_read, rewrite or log handler, so its scenarios (`proxy_*`, `auth`,
`route_json_*`, `ruby_call_*`) each skip six calls per request. The
expected change is a small decrease; `filter` uses a location-level filter
and keeps its path.

**Depends on.** Nothing. It edits `ngx_http_mruby_handler_init` and the
location configuration, as 2.5 and 2.10 do (section 4).

### 2.5 The directive table, and one duplicate check

**Today.** Each HTTP handler kind is written out in five places: the
command table (`src/http/ngx_http_mruby_module.c:163-288`), the location
configuration fields (`src/http/ngx_http_mruby_module.h:95-121`), create,
merge and cleanup (`src/http/ngx_http_mruby_module.c:451-567`), one
directive function per directive (`:1652-1861`), and the handler functions
and their registration (`:640-723`, `:1952-2033`). A second directive for
the same code gives "is duplicated" in HTTP (`:1490-1492`, `:1514-1516`),
which also covers the file and inline forms of `mruby_init`,
`mruby_init_worker` and `mruby_exit_worker`, which share one field. The
file and inline forms of a phase handler are two handlers, and both run.
In stream, a later directive replaces the earlier one without a message
(`ngx_stream_mruby_replace_code`,
`src/stream/ngx_stream_mruby_module.c:452-461`), also between
`mruby_stream` and `mruby_stream_code`.

**Design.**

- One table, written once as an X-macro, with a row per HTTP handler kind:
  the phase, the file and the inline directive, the contexts, and the
  field. The command entries, the configuration fields (an array indexed by
  kind and form), create, merge, cleanup, the handler functions and their
  registration are generated from it. Adding a field touches the table. The
  stream module has its own small table of the same form.
- One function for both modules sets the code of a directive: it refuses a
  field that is already set with "is duplicated", in HTTP and in stream
  (decision 4), loads the code through 2.6, and records the use for 2.4.
  In stream, `mruby_stream` and `mruby_stream_code` share one field, and so
  do the file and inline forms of each worker and init hook.

**Behavior change.** None in HTTP. In stream, `nginx -t` refuses a
configuration that gives a stream hook twice in one context: one entry.

**Test that fails first.** For the stream refusal, a case in
`test/t/cases/config_hooks.rb` style that starts nginx with `mruby_stream`
and `mruby_stream_code` in one `server {}` and expects `nginx -t` to fail;
today it starts. The table itself is checked by the whole suite passing
unchanged.

**Perf.** The generated handlers do what the written ones do; no change is
expected, and the pull request measures it.

**Depends on.** Nothing. It rewrites the directive functions, which 2.4
and 2.6 also change, and the registration in
`ngx_http_mruby_handler_init`, which 2.4 and 2.10 also change. By the rule
of section 4, it is not written at the same time as those pull requests,
and the one that merges second updates its branch.

### 2.6 Common layer: code loading

**Today.** HTTP and stream each have their own `ngx_mrb_code_t`
(`src/http/ngx_http_mruby_module.h:27-37`,
`src/stream/ngx_stream_mruby_module.h:29-37`), their own functions that
make a code from a file or a string (`src/http/ngx_http_mruby_module.c:1356-1395`,
`src/stream/ngx_stream_mruby_module.c:339-380`) and their own compile
function (`src/http/ngx_http_mruby_module.c:1428-1482`,
`src/stream/ngx_stream_mruby_module.c:382-425`). HTTP also reads a file
again on each request when neither `cache` nor `mruby_cache on` is given
(`ngx_http_mruby_state_reinit_from_file`,
`src/http/ngx_http_mruby_module.c:1330-1354`, called at `:1082-1093` and
`:2523`). A compiled proc is kept from the GC by the GC arena of the time
the configuration was read (the comment at
`src/stream/ngx_stream_mruby_module.c:452-456`; unverified), not by a
registration.

**Design.** `src/common/ngx_mruby_code.{h,c}` with one `ngx_mrb_code_t`
and four functions: make from a file, make from a string, compile (load,
prepare the proc with `ngx_mrb_fiber_prepare_proc`, free the compiler
context), and reload (the HTTP path without cache). The compiled proc is
kept in a slot of the GC root holder for the life of the state, and a
reload replaces the proc in the slot; this is the "mark cached procs"
part of the filter row of the plan, done here because it belongs to
loading. Stream keeps compiling once.

**Behavior change.** None.

**Test that fails first.** None: a change without a change of behavior.
The suite, the sanitizer cell and the valgrind cell check it; the pull
request also runs the suite with `-DMRB_GC_STRESS` (which `test.sh` adds)
on a configuration without `cache`.

**Perf.** `file` uses `cache`; no scenario reloads per request. No change
is expected.

**Depends on.** Nothing.

### 2.7 Common layer: upstream switching

**Today.** `Nginx::Upstream#server=` (`src/http/ngx_http_mruby_upstream.c:150-262`)
and `Nginx::Stream::Connection#upstream_server=`
(`src/stream/ngx_stream_mruby_connection.c:113-216`) are copies: the same
checks of the string, `ngx_parse_url` with `no_resolve`, a per-worker store
keyed by the peer and reset per cycle, and the assignment to the peer.
They differ in the peer type, in the locks (HTTP takes the peer locks), and
in an allocation failure (HTTP returns nil, stream raises).

**Design.** `src/common/ngx_mruby_upstream.{h,c}` with the checks and the
parse, and the per-worker store keyed by an opaque peer pointer. Each
protocol keeps the assignment to its own peer type, its locks, its
messages and what it does on an allocation failure.

**Behavior change.** None.

**Test that fails first.** None; the existing cases of both setters run
unchanged.

**Perf.** No scenario calls these setters.

**Depends on.** Nothing.

### 2.8 Common layer: error logging

**Today.** HTTP logs an exception in four functions
(`src/http/ngx_http_mruby_core.c:81-127`) that differ in the log and the
text, and logs the backtrace in builds with `--with-debug` (`:63-79`).
Stream has three more (`src/stream/ngx_stream_mruby_module.c:270-294`)
without the backtrace. `Nginx.log` has two copies
(`src/http/ngx_http_mruby_core.c:556-573`,
`src/stream/ngx_stream_mruby_core.c:30-47`).

**Design.** One function in `src/common/` logs an exception with a given
log, level and prefix, and the backtrace in debug builds; the callers pass
today's texts. One `Nginx.log` takes the log from the current context of
2.1 (or from the caller's lookup, if 2.1 is not merged yet).

**Behavior change.** Stream logs the backtrace in builds with
`--with-debug`: a "New features" entry. The lines of `error.log` keep their
text.

**Test that fails first.** None for the shared function. The stream
backtrace is checked by a case that runs only in the debug build of the
suite, if the suite has one; otherwise the pull request quotes a run.

**Perf.** No scenario raises.

**Depends on.** Nothing.

### 2.9 Waits inside another mruby call

**Today.** A handler that waits returns `NGX_DONE`, and the wake makes
nginx call it again, so that the checker of its phase ends it
(`src/http/ngx_http_mruby_module.c:1131-1135`). That holds only when no
other mruby call runs (`mrb->jmp == NULL`) and the module context is the
one the handler started with. Otherwise (`:1137-1143`) the timer or the end
of the subrequest resumes the fiber and ends its handler there, in
`ngx_mrb_post_fiber` (`src/http/ngx_http_mruby_async.c:413-509`): it calls
`ngx_mrb_finalize_rputs` itself, runs the phases on for `NGX_DECLINED`
(`:504-507`), and a content handler there does not keep the request, so the
request ends at the sleep. Such a handler runs because `Nginx.redirect`
with a local URI redirects inside the Ruby call in `mruby_set` handlers
and filters, and in a handler that `ngx_mrb_post_fiber` resumes
(`src/http/ngx_http_mruby_core.c:671-679`,
`src/http/ngx_http_mruby_async.c:717-751`); nginx then runs the handlers of
the target inside that call. Log handlers did so as well until #770, which
makes the call raise there. The module context is replaced when such a
redirect happens while a handler of the request is ending, for example in
an mruby header filter, which nginx runs when `ngx_mrb_finalize_rputs`
(`src/http/ngx_http_mruby_core.c:347`) or `ngx_mrb_send_empty_body`
(`:241`) sends the response, after the Ruby code of the handler has
returned. `Nginx.send_header`, `Nginx.return` and `Nginx.status_code=`
(`ngx_mrb_send_header`, `:425-467`) only set the status and mark the
output; they do not run the header filters.

**What is wrong.** Two ways to end a handler after a wait remain, and the
second ends the request in a way that no phase checker controls. It runs
Ruby from a timer outside nginx's phases, which is what the core
stabilization removed elsewhere.

**Design** (decision 1):

- `Nginx.redirect` with a local URI raises `RuntimeError` in `mruby_set`
  handlers, log handlers and header and body filters, as `Nginx::Async`
  does there. The redirect then has one rule: a local URI takes effect when
  the handler ends, and a handler whose end cannot take it raises. No
  handler of a request runs inside another mruby call through ngx_mruby
  any more. The mruby filters run when `ngx_mrb_finalize_rputs` or
  `ngx_mrb_send_empty_body` sends the response, after the Ruby code of the
  handler has returned, and they cannot wait anyway. A redirect with a URL (`http://`, `https://`,
  `$scheme`) only sets `Location` and the status, and keeps working there.
  The raise in log handlers, with its test and its entry in the release
  notes, is done by #770, the pull request of 2.10: after it, the
  log-phase handlers after the mruby log handlers run on the same request.
  The pull request of this section adds the raise for `mruby_set` handlers
  and the filters.
- As a guard, a handler that starts while the fiber of another handler
  runs is marked in its record (`ngx_http_mrb_running` is set when its
  fiber starts, or the context of 2.1 says so). In such a handler, and in a
  handler whose module context was replaced during its run,
  `Nginx::Async.sleep` and `Nginx::Async::HTTP.sub_request` raise
  `RuntimeError`, as in log handlers since 2.7.1.
- `ngx_mrb_post_fiber`, `by_post_fiber`, the branch at
  `src/http/ngx_http_mruby_module.c:1137-1143` and the `NGX_AGAIN` that a
  waiting handler returns there are removed. Every wait ends through the
  wake and nginx's checker.

**Behavior change.** Yes, one entry: `Nginx.redirect` with a local URI
raises in `mruby_set` handlers and filters, where today it runs the
target's handlers inside the call, and a content handler there that waits
ends the request at the sleep. Log handlers have their own entry, added
by #770; this pull request does not add a second one.

**Test that fails first.** `test/t/cases/redirect_nested.rb`: an
`mruby_set_code` handler that calls `Nginx.redirect "/target"`, and a target
whose content handler sleeps and answers; the request answers 500 and
`error.log` has the `RuntimeError` of `Nginx.redirect`. Today the redirect
runs, and the request ends at the sleep. The case of a log handler is in
`test/t/cases/log_before_access_log.rb` (the location `/redirect`), added
by #770; this pull request does not add a second one. No other case
redirects from an `mruby_set` handler or a filter (a search of
`test/conf` for `Nginx.redirect`).

**Perf.** `sleep` and `sub_request` go through the wake today and keep it;
one comparison is added when a fiber starts. No change is expected.

**Depends on.** Nothing. If 2.1 is merged first, the mark comes from the
context; if not, from `ngx_http_mrb_running`.

### 2.10 Log handlers before `access_log`

**Today.** `ngx_http_mruby_handler_init` appends the two mruby log handlers
to the log phase (`src/http/ngx_http_mruby_module.c:708-715`) in
ngx_mruby's postconfiguration, which nginx runs after that of its log
module, so `ngx_http_log_handler` runs first and writes the `access_log`
line before the mruby code sets anything. An exception in any handler sets
`r->headers_out.status` to 500 (`:1152`), log handlers included.

**Design.**

- In postconfiguration, the mruby log handlers go to the front of
  `cmcf->phases[NGX_HTTP_LOG_PHASE].handlers`: they run before every log
  handler that was registered before ngx_mruby's postconfiguration,
  `ngx_http_log_handler` among them. Modules whose postconfiguration runs
  later still append after them.
- A log handler does not change the status that `access_log` and the later
  log handlers see: `r->headers_out.status` is put back after each mruby
  log handler, after an exception and after a status that the code set.
  With 2.1, a status set in a log handler raises in any case (the response
  head is sent).

**Behavior change.** Yes, one entry: `access_log` and later log-phase
handlers see the variables that mruby log handlers set, and the status
stays the one sent (the plan's row; item 15 of section 7).

**Test that fails first.** `test/t/cases/log_before_access_log.rb`: a
`server {}` with a `log_format` that writes `$log_value`, a variable
declared with `set $log_value "unset"` (or with `mruby_variable` once 2.11
is in), and an `mruby_log_handler_code` that assigns `"from-ruby"`. The
`access_log` line has `unset` today. A second request whose log handler
raises checks that the line still has the status sent.

**Perf.** No scenario has a log handler. The order of the array costs
nothing per request.

**Depends on.** Nothing. It edits `ngx_http_mruby_handler_init`, as 2.4 and
2.5 do.

### 2.11 `mruby_variable`

**Today.** A variable that Ruby assigns must be declared by nginx, in
practice with `set`. A `set` at `server` level runs in the server rewrite
phase after ngx_mruby's server rewrite handler and overwrites what it
assigned, so configurations declare such variables in a location that is
never requested; the soak lane does this (`test/soak/nginx.agent.conf:101-110`).
`Nginx::Var` assigns an indexed variable by writing
`r->variables[index]` (`src/http/ngx_http_mruby_var.c:155-156`).

**Design.** `mruby_variable $name [value];` in the `http {}` block.

- It declares `$name` as a changeable, indexed variable with a get handler
  of ngx_mruby. Before Ruby assigns it in a request, reading it gives
  `value`, a complex value that may contain variables, as the value of
  `set` may; without `value`, the empty string.
- A name that another module defines with a value of its own (for example
  `$uri`) is refused when the configuration is read. A name that `set` also
  assigns is accepted, and both assign it.
- Only `http {}`: a declaration is global in nginx, and a value per
  location would need code that runs per location, which is what the
  directive avoids.

**Behavior change.** None; a "New features" entry, and the directive in
`docs/directives/README.md`.

**Test that fails first.** `test/t/cases/mruby_variable.rb`: a server
rewrite handler assigns `$agent_key`, a content handler answers it, and a
second location answers the declared default without an assignment; a
second nginx started by the case with `mruby_variable $uri;` fails
`nginx -t`. Today `nginx -t` refuses the unknown directive.

**Perf.** None in the existing scenarios. The soak configuration can then
drop its declaration-only location, in a later pull request, so that the
comparison of this one stays on the same configuration.

**Depends on.** Nothing.

### 2.12 A body with any status

**Today.** `Nginx.return`, `Nginx.send_header` and `Nginx.status_code=`
(`ngx_mrb_send_header`, `src/http/ngx_http_mruby_core.c:425-467`) set the
status, and when the handler wrote output with `Nginx.rputs`, mark its
last buffer (`:442-445`). When the handler ends,
`ngx_mrb_finalize_rputs` (`:283-367`) sends the output with the status
(`:334-361`) when the status is 200, when it was set before the output
(the last buffer is not marked), or when the content phase would leave the
client without a response (`ngx_mrb_content_ends_without_response`,
`:150-161`: a content handler of the main request, and a status below 300
other than 201 and 204). Otherwise it returns the status (`:364-366`) to
the phase checker, which passes it to `ngx_http_finalize_request`, and the
output is dropped:

- For 201, 204 and the statuses from 300 up, nginx sends its own page for
  the status, and an `error_page` of the location for that status applies.
  So `Nginx.rputs '{"error":"no key"}'` followed by `Nginx.return
  Nginx::HTTP_UNAUTHORIZED` answers nginx's 401 page, in a content handler
  and in post_read, server rewrite, rewrite and access handlers.
- In post_read, server rewrite, rewrite and access handlers and in
  subrequests, a status below 300 other than 200, 201 and 204 (for example
  202 after output in an access handler) is returned to the phase checker
  in the same way, and the output is not sent.
- In a content handler of the main request, a status below 200 set after
  output is sent as the status of the final response.

**What is wrong.** Whether the output of a script is sent depends on
whether it set the status before or after the output. The agent proxy
answers 401, 403 and 429 with JSON bodies that Ruby builds (section 4 of
the plan, the Pillar B rows the proxy needs), and item 8 of section 7 of
the plan accepted "body with any status".

**Design.**

- In `ngx_mrb_finalize_rputs`, output that the handler wrote is sent with
  the status that the handler set, before or after the output, through
  the branch that sends output today. For the statuses other than 301,
  302, 303, 307 and 308 this is what nginx's `return code text` does
  (`ngx_http_send_response`). This holds for every handler that sends
  output today: post_read, server rewrite, rewrite, access and content
  handlers, of the main request and of subrequests.
- Every status from 200 up is sent with the output: 201, the statuses
  below 300 that the phase checkers now get back (202 and the like), and
  the statuses from 300 up. `Content-Length` counts the output. A HEAD
  request gets the header only, as today (`r->header_only`).
- For a status from 300 up, ngx_mruby adds no `Location`: a script that
  writes output and sets 301, 302, 303, 307 or 308 without setting
  `Location` itself (with `headers_out` or `Nginx.redirect` with a URL)
  sends its output with that status and no `Location`.
- 204 and 304: nginx's header filter sets `r->header_only` for both
  (`src/http/ngx_http_header_filter_module.c:230-231` and `:248-249` in
  nginx 1.31.8), and `ngx_mrb_finalize_rputs` does not send the output
  when `r->header_only` is set (`:349-356`), so the header is sent without
  the output. The test checks it.
- A status below 200 after output answers 500, as a content handler
  without output and with such a status does today
  (`ngx_mrb_answer_missing_body`, `:167-178`).
- A negative result such as `Nginx::DECLINED` after the output keeps
  today's handling: the output is not sent, and the phase gets the code
  (`:329-333`). An exception still drops the output and answers 500
  (`src/http/ngx_http_mruby_module.c:1148-1177`).

**`error_page` (decision 5).** Today an `error_page` of the location for
the status applies after such output, because nginx sends the response for
the status. With the design, the handler sends its output with the status,
and `error_page` does not apply to that response. For the statuses other
than 301, 302, 303, 307 and 308, this is how nginx treats its own `return`
with a text: `ngx_http_script_return_code` sends it with
`ngx_http_send_response`, which sends the response itself and does not go
through `error_page` (`src/http/ngx_http_script.c:1577-1582` in nginx
1.31.8; `error_page` is applied by `ngx_http_special_response_handler`).
For those five statuses, nginx takes the text of `return` as the
`Location` and answers through `ngx_http_special_response_handler`, where
`error_page` applies (`ngx_http_send_response`,
`src/http/ngx_http_core_module.c:1845-1864`); the text is not a body
there, so nginx has no case to compare with, and the reason for one rule,
"the output of a handler is sent with its status", applies to them as it
stands. A script that wants nginx's page, and its `error_page`, sets the
status without output, as today. Section 5 records the decision and the
option not chosen.

**Behavior change.** Yes, one entry in the release notes of 3.0.0: output
followed by a status set after it is sent with that status for every
status from 200 up, instead of nginx's page (201 and from 300 up) or of
dropping the output (the statuses below 300 other than 200, 201 and 204 in
post_read, server rewrite, rewrite and access handlers and in
subrequests), and
output followed by a status below 200 answers 500. The entry also says that `error_page` no longer applies to such a response: a
configuration that writes output, sets a status from 300 up after it and
relies on an `error_page` for that status now sends the output, and gets
nginx's page again by setting the status without output.

**Test that fails first.** `test/t/cases/body_with_status.rb`: a content
handler that writes a JSON body and then calls `Nginx.return
Nginx::HTTP_UNAUTHORIZED` answers 401 with that body and its
`Content-Length` (today nginx's 401 page); an access handler that does the
same with 429; a HEAD request to the first location gets the header only;
output followed by 204 gets 204 without a body; output followed by 101
gets 500. The pull request lists every existing expectation that changes,
for the owner's approval that `AGENTS.md` asks for.

**Perf.** No scenario sets a status after its output; the change is in the
condition of a branch. No change is expected.

**Depends on.** Nothing. It edits
`src/http/ngx_http_mruby_core.c`, as the execution context does
(`Nginx.send_header`).

## 3. Verification for `v3.0.0-alpha.1`

Step 4 of the plan tags alpha.1 "when the v2 suite passes under the new
core with sanitizers clean". After the pull requests of section 4, a check
pull request to `next`:

- runs the suite of `next`, the ASan and UBSan cell and the cell under
  valgrind on its head (the label `full-matrix` runs every cell);
- lists the case files of `test/t/` on `master` whose expectations differ on
  `next` (`git diff origin/master origin/next -- test/t`), and for each
  difference the entry of `docs/releases/v3.0.0.md` that explains it; a
  difference without an entry is a "must fix";
- checks the release notes as "Before the tag" in
  `docs/releases/README.md` describes: it lists every pull request merged
  into `next` since the start of the range, the latest 2.x release tag for
  the first pre-release (`v2.7.5` today), confirms the entries of each in
  `docs/releases/v3.0.0.md`, and compares `docs/releases/v3.0.0.ja.md` with
  the English file;
- compares the performance of its head with the same tag, as "Before a
  tag" in `AGENTS.md` describes, and sends a `WARN` or `FAIL` to the owner.

The session publishes the tag after the owner's go-ahead for that release.

## 4. The pull requests

One pull request per row, each to `next` with its tests, its release notes
entries in English and Japanese, and its documentation. A bug fix comes as
a test commit and a fix commit. "Waits for" names only what the design
needs: a decision that is still open, or another pull request. "Edits the same
code as" names the rows that change the same functions; by "Branches and
pull requests" in `AGENTS.md`, such rows are not written at the same time,
and the one that merges second updates its branch.

| Pull request | Section | Waits for | Edits the same code as |
|---|---|---|---|
| Log handlers before `access_log`: [#770](https://github.com/matsumotory/ngx_mruby/pull/770), done when it is merged; #770 also makes `Nginx.redirect` with a local URI raise in log handlers, the log handler part of 2.9 | 2.10, 2.9 | nothing | filter handlers, directive table (`ngx_http_mruby_handler_init`) |
| `mruby_variable` | 2.11 | nothing | nothing |
| Headers | 2.2 | nothing | execution context (`src/http/ngx_http_mruby_request.c`) |
| Filter handlers: type, merge, phase handlers only where used | 2.4 | nothing | log handlers, directive table, code loading (the directive functions) |
| Execution context and the phases of the Ruby API | 2.1 | nothing | headers, `Nginx::Var`, per-request store, waits inside another call, error logging, a body with any status |
| Per-request store | 2.1 | nothing | execution context |
| One setter for `Nginx::Var` | 2.3 | nothing | execution context (`src/http/ngx_http_mruby_var.c`), waits inside another call (the caller of the setter in `ngx_mrb_post_fiber`) |
| Waits inside another mruby call (the raise of `Nginx.redirect` in log handlers is done by #770) | 2.9 | nothing | execution context (`src/http/ngx_http_mruby_async.c`), `Nginx::Var` |
| Common code loading | 2.6 | nothing | directive table, filter handlers (the directive functions) |
| Common upstream switching | 2.7 | nothing | nothing |
| Common error logging | 2.8 | nothing | execution context (`Nginx.log`) |
| Directive table and one duplicate check | 2.5 | nothing | log handlers, filter handlers, code loading |
| A body with any status: [#779](https://github.com/matsumotory/ngx_mruby/pull/779), done when it is merged | 2.12 | nothing | execution context (`src/http/ngx_http_mruby_core.c`) |
| The check before the tag | 3 | every row above | nothing |

The agent proxy parts (a) and (c) of step 7 of the plan do not touch these
functions, except that the upstream peer hook adds a directive, which the
directive table then lists.

## 5. Decisions and rationale

The five decisions below were made on 2026-11-09. Each records what was
chosen, the option that was not, the reason, and what changes. Sections
2.1, 2.3, 2.5, 2.9 and 2.12 describe the design with them.

### Decision 1: `Nginx.redirect` to a local URI raises in `mruby_set` handlers, log handlers and output filters

Chosen: the redirect raises `RuntimeError` in these three kinds of handler,
as `Nginx::Async` does there. Not chosen: keeping the redirect inside the
Ruby call and making a handler of the target raise when it waits.

Reason: the redirect gets one rule in every handler (it takes effect when
the handler ends, or raises where that cannot happen), and no handler of a
request runs inside another one, so every wait ends through nginx's phase
checker and `ngx_mrb_post_fiber` goes away. In a log handler the response
is already sent, and in a filter it is being sent, so a redirect there has
no response left to make; in an `mruby_set` handler the rewrite script
goes on after the call. No case of the suite uses the redirect in these
handlers.

What changes: a script that redirects to a local URI from these handlers
gets the exception, and sends the request elsewhere from a phase handler
instead; one entry in the release notes (section 2.9).

### Decision 2: the store of `Nginx::Request#store` survives internal redirects

Chosen: the store belongs to the request. A cleanup of the request pool
holds it, and a handler that runs after an internal redirect (`error_page`,
`try_files`, a named location, `Nginx.redirect`) finds it there. Not
chosen: clearing it with the module contexts, as `ngx.ctx` of OpenResty is
cleared.

Reason: the agent proxy sends a request that gets a 529 to another provider
with `error_page 529 = @name`, an internal redirect, and its log handler
then charges the usage to the key that the authentication handler stored.
With a store that the redirect clears, that key would have to go through a
variable. The cost is a walk of the cleanups of the request pool, once per
handler after a redirect, and only for requests that use the store.

What changes: a new method; no existing script changes (section 2.1).

### Decision 3: assigning a variable that nginx does not know, or does not let scripts change, raises

Chosen: `NameError` for a name that nginx does not know, and `RuntimeError`
for a variable that nginx does not let scripts change. Not chosen: keeping
the error line and the nil return.

Reason: a misspelled variable then fails at the first request that runs
the assignment, with its exception in `error.log`, instead of losing the
value with only an error line and the request going on. The worker does
not stop; a handler that wants to go on rescues the exception. `nginx -t`
cannot find these mistakes, because Ruby code decides the name per
request (section 2.3 says which mistakes stop nginx when it reads the
configuration and which show at the first request). With
`mruby_variable`, every variable that a script means to assign can be
declared, so a correct configuration does not reach the exception.

What changes: a handler that assigns such a variable answers 500 where it
went on, and a log handler logs the exception; one entry in the release
notes (section 2.3).

### Decision 4: a stream hook given twice in one context fails `nginx -t`

Chosen: stream refuses the second directive with "is duplicated", as HTTP
does; `mruby_stream` and `mruby_stream_code` count as the same hook, and so
do the file and inline forms of each init and worker hook. Not chosen:
keeping the replacement without a message.

Reason: the code that a configuration means to run is then the code that
runs, and both modules share one rule and one function (section 2.5).

What changes: a configuration that gives a stream hook twice fails
`nginx -t` on 3.0.0 and has to remove one of them; one entry in the
release notes.

### Decision 5: output followed by a status is sent with that status, and `error_page` does not apply to it

Chosen: the output that a handler wrote is sent with the status that the
handler set after it, and an `error_page` of the location for that status
does not apply to the response. Not chosen: dropping the output and
letting `error_page` apply when the location has one for the status, and
sending the output otherwise.

Reason: one rule, "the output of a handler is sent with its status". For
the statuses other than 301, 302, 303, 307 and 308 it is the same as
nginx's own `return` with a text, which `ngx_http_script_return_code` sends
with `ngx_http_send_response` without going through `error_page`
(`src/http/ngx_http_script.c:1577-1582` in nginx 1.31.8). For those five
statuses, nginx takes the text as the `Location`, not as a body, and
answers through `error_page`, so nginx has no case to compare with, and
the reason for the one rule applies to them as it stands. With the option
not chosen, what a script sends would depend on directives elsewhere in the
configuration, and `ngx_mrb_finalize_rputs` would search the `error_page`
list of the location for each such response.

What changes: a configuration that writes output, sets a status from 300
up after it and relies on an `error_page` for that status sends the output
on 3.0.0; it gets nginx's page again by setting the status without output.
The entry of section 2.12 in the release notes of 3.0.0 says so.

## 6. Risks

- The execution context replaces a lookup in every method. A method that
  the pull request misses keeps the old lookup and works where it worked;
  the pull request lists every method and its mask, and the case file of
  2.1 calls one method of each row in each handler kind.
- Raising where a method had no effect can reach scripts that called such
  methods by habit, for example setting a response header in a log handler.
  The release notes entry lists the table, and the migration guide gets
  the same table.
- Moving log handlers to the front changes the order against third-party
  log-phase modules whose postconfiguration runs before ngx_mruby's. The
  entry says that mruby log handlers run before those modules.
- `Content-Type` and `Content-Length` set through `headers_out` now reach
  nginx's fields, which later filters (gzip, charset, range) read. A script
  that set them for show now changes what those filters do; the entry says
  so.
- The merge of filters makes a server-level filter run in locations that
  proxy or serve files, with `r->filter_need_in_memory` set there.
- HTTP/2 and HTTP/3 clients are not in the harness yet (the queue row on
  the harness), so the behavior changes are tested over HTTP/1.x only.

## 7. Security review

The pull requests of section 4 change code where several of the advisories
of 2026 were (see section 1 of
[the core stabilization proposal](archive/core-stabilization.md)). A
finding on this code goes to the process of [SECURITY.md](../../SECURITY.md),
not into a pull request or this file.
