# Proposal: the frame in which handler code runs (#502)

Status: done and archived (decided on 2026-10-15). The owner chose option (a) of section 4:
keep the top-level frame, with the regression test and the docs. The steps of
section 5 for (a) are done: the test and the release notes entry in #584
on `next`, the note in the docs of `master` in #586, and #502 is closed
(section 7, item 14, of the v3 plan). Written from `next`
at acdc82fb1 (mruby 4.0.0, nginx 1.31.6), `master` at 0a1e8acb3 (mruby
3.3.0) for comparison, [the triage comment on
#502](https://github.com/matsumotory/ngx_mruby/issues/502#issuecomment-5977615799)
(2026-10-04), and measurements made on 2026-10-15 in the container image
`ngx-mruby-dev:22.04` (Ubuntu 22.04, gcc 11.4.0, valgrind 3.18.1) on
aarch64. Section 4 holds the question that the owner answered, with the
recommendation.

## 1. The problem

### 1.1 What #502 reports

#502 shows two rewrite handlers that set `Location`, call
`Nginx.return Nginx::HTTP_MOVED_TEMPORARILY` and then `return`: once inside
`[0].each do ... end`, once inside `for _ in [0] ... end`. On `master` both
answer 500, and `error.log` has `unexpected return (LocalJumpError)`. The
same handler with the `return` at the top level of the code answers 302.
The triage gave the owner two ways out:

1. Run handler code in a method or lambda frame, so that such a `return`
   ends the handler. This changes behavior.
2. Keep the behavior and document it: end a handler with a top-level
   `return`, or put the code in a method.

It proposed to measure option 1 before the decision: what it changes for
`self`, local variables and constant lookup in handler code, and what one
more frame costs per request. This document is that measurement.

### 1.2 How handler code is compiled and run

Line numbers are those of `next` at acdc82fb1.

- Compile. `ngx_http_mruby_shared_state_compile`
  (`src/http/ngx_http_mruby_module.c:1025`) gives each piece of code its
  own `mrbc_context` (`:1031`), sets `no_exec` (`:1032`), and compiles the
  code as a top-level script with `mrb_load_file_cxt` (`:1042`) or
  `mrb_load_string_cxt` (`:1046`). A handler file without `cache` (and
  without `mruby_cache on`) is compiled again on every request, in the same
  way (`ngx_http_mruby_state_reinit_from_file`, `:933` to `:946`).
- Run. `ngx_mrb_run` (`:788`) passes the compiled proc to
  `ngx_mrb_start_fiber` (`:864`). `ngx_mrb_start_fiber`
  (`src/http/ngx_http_mruby_async.c:137`) clears the proc's environment
  (`handler_proc->upper = NULL`, `:150`), sets its target class to `Object`
  (`:151`), makes a new fiber of it (`mrb_fiber_new`, `:168`) and resumes
  the fiber with no arguments (`mrb_fiber_resume`, `:205`). Every request
  handler, filter and `mruby_set` runs this way. The stream module does the
  same (`src/stream/ngx_stream_mruby_async.c:62` to `:65`).
- The receiver. A new fiber whose proc has no environment gets the
  top-level object `main` as `self`
  (`mruby/mrbgems/mruby-fiber/src/fiber.c:274` to `:281`). The rest of the
  fiber's stack, where the local variables live, starts as `nil` (`:42` to
  `:47`).
- The request. No `Nginx::Request` or `Nginx::Var` is passed to the code.
  The code makes them (`Nginx::Request.new`), and they find the current
  request with `ngx_mrb_get_request()`
  (`src/http/ngx_http_mruby_request.c:93`), which `ngx_mrb_run` sets with
  `ngx_mrb_push_request()` (`:87`) before it runs the code.
- After a request. `ngx_mrb_state_clean`
  (`src/http/ngx_http_mruby_module.c:724`) clears only `mrb->exc`
  (`:726`).
- Other code. `mruby_init_code`, `mruby_init_worker_code`,
  `mruby_exit_worker_code`, the server configuration code and the SSL
  handshake handler do not run in a fiber: they run with `mrb_toplevel_run`
  (`:739`, `:755`, `:2126`, `:2129`), which also gives them `main` as
  `self` (`mruby/include/mruby.h:1354` to `:1355`).

### 1.3 Why #502 fails on `master` and not on `next`

A `return` inside a block compiles to the instruction `OP_RETURN_BLK`. mruby
finds the frame to return from (the frame of the nearest method or lambda
that encloses the block, or else the top-level frame: `top_proc`), then
looks for that frame on the call stack of the current fiber.

- mruby 3.3.0 (`master`) refuses a frame at the bottom of that stack:
  `if (ci <= cibase) { /* no jump destination */` (`mruby/src/vm.c:2322`
  on `master`) raises `LocalJumpError`. Handler code is exactly there: it
  is the first frame of its fiber. A plain mruby 3.3.0 script is the bottom
  frame of the root context in the same way, which is why the triage got the
  same error from `[0].each { return }` at the top level of a script.
- mruby 4.0.0 (`next`, since #561) searches down to and including the
  bottom frame (`for (ptrdiff_t i = ci - mrb->c->cibase; i >= 0; i--, ci--)`,
  `mruby/src/vm.c:2770`) and matches the frame by its environment (`:2761`
  to `:2779`). The loop came with mruby/mruby@682583a609 (2024-08-12,
  "Shrinking the code in `OP_BREAK` and `OP_RETURN_BLK`"), the match by
  environment with mruby/mruby#6412 (merged 2024-11-10). Both came after
  mruby 3.3.0.

Measured on `next` (section 3.1): both locations of #502 answer
`302 Moved Temporarily` with `Location: http://example.com`, as the
top-level `return` does, and `error.log` has no line at the `error` level.
In a `mruby_set_code`, `[0].each { return "from block" }; "after block"`
sets the variable to `from block`. Plain mruby 4.0.0
(`mruby/build/host/bin/mruby` of the `test.sh` build) runs
`[0].each { |x| p :in_block; return }; p :after`, prints `:in_block`, does
not print `:after` and exits with 0; the `for` form does the same.

So on `next`, #502 is fixed by the update to mruby 4.0.0, without a change of
the frame. No test on `next` covers it yet.

### 1.4 What handler code shares today

Measured on `next` with the scenario of section 3.1: one worker, one
location that sets a local variable, a constant, an instance variable of
`self`, a global variable and a method, and other locations that read them,
each requested in turn.

| What the code does | Seen by other handler code of the same worker | Seen on the next request | Why |
|---|---|---|---|
| Reads `self` | The same object, `main` (the same `object_id` in every location) | The same object | 1.2, the receiver |
| Assigns a local variable | No: another location gets `NoMethodError: undefined method 'n' for Object`, and so does the content handler of the request whose rewrite handler assigned it | No: `n ||= 0; n += 1` gives `n=1` on every request | Each piece of code has its own compile context and runs in a new fiber whose stack starts as `nil` (1.2) |
| Assigns a constant (`C502 = ...`) | Yes | Yes: 1, then 2 | The target class is `Object` (1.2) |
| Sets an instance variable of `self` (`@iv502`) | Yes; `instance_variables` of `main` lists it | Yes: 1, then 2 | `self` is `main` |
| Sets a global variable (`$g502`) | Yes | Yes: 1, then 2 | `ngx_mrb_state_clean` clears only the exception (1.2) |
| Defines a method with `def` | Yes, a public method of `Object`: another location can call it with any receiver (`"x".helper502b`) | Yes | `def` at the top level defines on `Object`, with the visibility of the frame (see below the table) |
| Defines a class (`class Handler502`) with a constant in it | Yes | Yes; the class is reopened on each run | As for constants |

A `def` in handler code defines a public method, where a plain mruby 4.0.0
script defines a private one (`"x".h502` raises `private method 'h502'
called for String`). mruby takes the visibility of a `def` from the frame
that runs it (`mruby/src/class.c:1058` to `:1060`). The first frame of the
root context starts as private (`c->ci->vis = 1`, `mruby/src/vm.c:130`),
and the first frame of a fiber starts as zero, which is public
(`mruby/mrbgems/mruby-fiber/src/fiber.c:55` to `:59`). Handler code runs in
the first frame of its fiber (1.2), so a helper that it defines can be
called on every object of the worker. Code that runs with
`mrb_toplevel_run`, such as `mruby_init_code`, runs in the root context and
defines private methods, as a plain script does. Measured with a second
configuration on `next` (3.1):

```text
GET /def_set    defined
GET /def_call   x.helper502b with the receiver x: helper502b called
                public_instance_methods(false) includes it: true
                private_instance_methods(false) includes it: false
plain mruby     "x".h502: NoMethodError: private method 'h502' called for String
                public_instance_methods(false) includes it: false
                private_instance_methods(false) includes it: true
```

The responses of the scenario, in the order of the requests (status lines
and headers left out; all were `200 OK`):

```text
GET /read   self=main id=187651254034216
            n of /set: NoMethodError: undefined method 'n' for Object
            C502=undefined   @iv502=nil $g502=nil   helper502=undefined
            instance_variables of self=[]
GET /set    self=main self.class=Object id=187651254034216
            local n=1 C502=1 @iv502=1 $g502=1
GET /set    self=main self.class=Object id=187651254034216
            local n=1 C502=2 @iv502=2 $g502=2
GET /read   self=main id=187651254034216
            n of /set: NoMethodError: undefined method 'n' for Object
            C502=2   @iv502=2 $g502=2   helper502=helper502 defined
            instance_variables of self=[:@iv502]
GET /two_phases (twice, the same response)
            rw_local of the rewrite handler: NoMethodError: undefined method 'rw_local' for Object; @rw_ivar="set in rewrite"
```

What this means for the question of #502:

- Local variables do not leak today, neither from one piece of code to
  another nor from one request to the next. A frame change cannot improve
  on that.
- What survives is what hangs on the shared `mrb_state` of the worker:
  `main` and its instance variables, constants, globals, methods and
  classes. An instance variable that one request sets on `self` is seen by
  every later request of the worker, of any client and in any location. A
  method or lambda frame keeps `self` as `main` and therefore changes none
  of this; only another `self` per request would. The one `mrb_state` per
  worker is a decision of the owner (AGENTS.md, "Design principles").
- Each worker has its own copy of the state after the fork, so this is
  shared by the requests of one worker, not between workers. The scenario
  ran one worker.
- `README.md` (line 153) and `docs/README.md` (line 76) said that the server
  process frees the global variables table between scripts. The
  measurement and `ngx_mrb_state_clean` show that `next` does not. #592 on
  `master` (merged on 2026-10-19) replaced those texts with what a worker
  keeps between requests, and #623 on `next` (merged on 2026-10-29) reduced
  `README.md` and `docs/README.md`, which no longer contain them.

## 2. Options

Every option keeps what section 1.4 lists: `self` is `main`; local
variables stay private to each piece of code and request; constants,
globals, instance variables of `self`, methods and classes are shared as
before; constant lookup starts at `Object`, since the target class of the
handler proc stays `Object`. The options differ in what the compiler
accepts, in the backtrace, in the cost per request, and in whether they
would also fix `master`.

| | (a) Keep the top-level frame | (b) A method frame | (c1) A lambda frame: the compiled proc marked as a lambda | (c2) A lambda frame: a wrapper lambda |
|---|---|---|---|---|
| `return` in a block or a `for` body, on `next` | Ends the handler (1.3) | Ends the handler | Ends the handler | Ends the handler |
| What the compiler accepts | As today | A constant assignment, `class` and `module` are a `SyntaxError`: `nginx -t` refuses the configuration | As today | The rules of a block: as today |
| Backtrace in `error.log` | As today | As today | As today | One more line, the line of the wrapper |
| `test.sh` (221 assertions) | 221 pass | 19 assertions use code that does not compile (2 (b)) | 221 pass | 220 pass; `ngx_mruby - backtrace log` fails |
| Ir per request in the perf lane (3.3) | No change | -0.31% to +1.75% where Ruby runs, all `ok` (about +62 per run in `ruby_call_10`) | Within 0.03%, as the prototype with the top-level frame | From +1,075 to +1,941 per run of handler code: `hello` +13.88%, `ruby_call_10` +33.92%; seven `FAIL` and one `WARN` |
| Would it fix `master` (mruby 3.3.0)? | No | No: the method body is still the bottom frame | No: the same | Yes: the lambda's frame is above the bottom frame |

### (a) Keep the top-level frame

- Scripts: nothing changes. On `next`, `return` in a block or in a `for`
  body of handler code ends the handler (1.3).
- To do: a regression test on `next` with the two locations of #502 and
  the assertions of a2ikm/ngx_mruby#2 (302 and the `Location` header). It
  passes on `next` today; it catches a later mruby update that would bring
  the error back. On `master`, #502 stays: the docs can say how to write
  such a handler in 2.x (a top-level `return`, or the code in a method or a
  lambda) and that v3 accepts the `return` in a block.
- Cost: none.

### (b) A method frame

How the prototype does it: the code is compiled as the body of a method
(`def __ngx_mruby_handler__; ` before the code on its first line, so that
line numbers stay, and `end` on a line after it), and the body runs as the
handler proc with the flags of a method body
(`MRB_PROC_SCOPE | MRB_PROC_STRICT`). No method is defined on `Object`, and
no frame is added per request.

- What the compiler accepts: the rules of a method body. A constant
  assignment is a `SyntaxError` (`dynamic constant assignment`), and so are
  `class` and `module` (`class definition in method body`). Such code makes
  `nginx -t` fail, as any syntax error in handler code does today. mruby
  4.0.0 already applies this rule inside a `def` (`docs/migration/README.md`,
  "Assigning a constant in a method body is a `SyntaxError`"); option (b)
  would apply it to the whole of every handler.
- Code that stops compiling in the test configuration: 12 pieces of
  handler code at 11 locations of `test/conf/nginx.conf`, used by 19
  assertions of `test/t/ngx_mruby.rb`, five of them stream tests that fetch
  `/mruby` through the stream proxies:

  | Location | What the code does | Assertions |
  |---|---|---|
  | `/mruby` (`test/html/unified_hello.rb`) | `Server = Nginx` | `ngx_mruby`, `ngx_mruby - update built-in response header in http context` |
  | `/all_instance` | `Server = Nginx` | `ngx_mruby - all instance test` |
  | `/rack_base`, `/rack_base1` to `/rack_base4`, `/rack_base_env` | `class RackTest` | `ngx_mruby - rack base` (seven: one per location, and a POST to `/rack_base_env`) |
  | `/rack_base_2phase` (access and content handlers) | `class AccessCheck`, `class RackTest` | `ngx_mruby - rack base auth ok`, `ngx_mruby - rack base auth ng` |
  | `/issue_238` | `class MyError < RuntimeError; end` | `ngx_mruby - Throw my own exception for issue 238` |
  | `/backtrace` (`test/html/backtrace.rb`) | `class Foo`, `class Bar` | `ngx_mruby - backtrace log` |
  | `/mruby` through the stream proxies on ports 12345, 12348, 12349, 12350, 12351 and 12352 | `Server = Nginx` | `ngx_mruby - stream tcp load balancer` (port 12345), `ngx_mruby - stream tcp port`, `ngx_mruby - stream tcp ip port text`, `ngx_mruby - add linstener`, `ngx_mruby - Nginx::Stream::Async.sleep` |

  A copy of the prototype whose fallback compiles
  `raise ScriptError, ...` in place of such code, and keeps the method frame
  when a file without `cache` is compiled again, makes each of these
  locations raise when it runs. With it, `NGX_MRUBY_PROTO_FRAME=method` and
  a copy of `test.sh` that goes on after a failed file, 15 of the 19 fail:
  13 `Fail` and 2 `Crash` (`JSON::ParserError` for the GET and the POST of
  `/rack_base_env`), the five stream assertions among them; every case
  file passes. The other four pass for reasons that have nothing to do with
  the code: the assertions of `/rack_base4` and `/issue_238` expect 500;
  `ngx_mruby - update built-in response header in http context` checks a
  `Server` header that other code sets; `ngx_mruby - backtrace log` counts
  three lines naming `backtrace.rb` in `error.log`, which in this copy are
  the two compile errors (nginx sends its stderr to `error.log`) and the
  line of the `raise`. The review of this proposal on #583 counted 16
  failures, that test among them, with a copy that compiles the `raise` in
  place of the file on each request, without compiling the file: only the
  line of the `raise` reached `error.log`, one of the three lines that the
  test counts.

- Documented examples that stop compiling: the quick start of
  `docs/install/README.md` (5-A and 5-B, `Server = Nginx`), the example of
  `README.md` and `docs/README.md` (`Server = get_server_class`), the
  `get_server_class` and `server_name` examples of
  `docs/class_and_method/README.md`, and its `run MyApp.new` example
  (`class MyApp`). The usual Rack-style handler, a class defined in the
  handler and passed to `run`, is among them.
- Everything else that the scenario and the suite check is the same as in
  (a): the responses of the scenario (3.1), and all 221 assertions when the
  prototype lets the code that does not compile fall back to the top-level
  frame (3.2). The cost is in the perf lane (3.3).
- `master`: it would not fix #502 there. The method body is still the first
  frame of the fiber, which mruby 3.3.0 refuses (1.3). This is read from
  the code; it was not measured on `master`.

### (c) A lambda frame

Two forms were measured.

**(c1) The compiled top-level proc marked as a lambda** (`MRB_PROC_STRICT`).
The prototype sets the flag when it compiles the code; a real change could
set it there or in `ngx_mrb_start_fiber` of HTTP and of stream, one line
each. No frame is added per request.

- Scripts: no difference measured. The responses of the scenario are those
  of `next` (only `object_id` and process ids differ), and all 221
  assertions pass. The compiler is not involved, so it accepts what it
  accepts today.
- `master`: it would not fix #502 there, for the reason given under (b).

**(c2) A wrapper lambda.** The code is compiled inside `->() do ` and
`end.call`, so that the top-level frame creates a lambda and calls it on
every run: one more frame. It is the form that the triage wrote by hand in
the handler code on `master` (`->() { ... }.call`), where it answers 302:
the lambda's frame is above the bottom frame of the fiber, which mruby 3.3.0
accepts.

- What the compiler accepts: the rules of a block, which accept constant
  assignments and class definitions as the top level does.
- Backtrace: one more line, the line of `end.call` after the code. For an
  exception at line 3 of the scenario's `/raise`, `error.log` has
  `INLINE CODE:3` and `INLINE CODE:5`, where `next` has `INLINE CODE:3`
  only.
- Tests: `ngx_mruby - backtrace log` fails: it counts four lines of
  `backtrace.rb` in `error.log` and expects three. The other 220
  assertions pass.
- Cost: on every run of handler code, a lambda and the environment that it
  captures are allocated, and `Proc#call` is called (3.3).

## 3. How it was measured

### 3.1 The standalone scenario

An nginx built by `sh test.sh` on `next` (acdc82fb1, nginx 1.31.6, built as
`test.sh` builds it, with `-DMRB_GC_STRESS`), started with a configuration
of its own (`worker_processes 1`, one server on port 18502) and requested
with `curl` in a fixed order. The locations:

- `/set`: `n ||= 0; n += 1`, `C502 = ...` (1, then one more on each
  request), `@iv502` and `$g502` (the same), `def helper502`; the response
  prints `self`, its class and `object_id`, and the values.
- `/read`: reads `n` (rescuing `NameError`), `C502`, `@iv502`, `$g502`,
  `helper502` and `instance_variables`.
- `/two_phases`: a rewrite handler sets `rw_local` and `@rw_ivar` and calls
  `Nginx.return Nginx::DECLINED`; the content handler of the same location
  reads both.
- `/const_lookup`: opens `class Handler502` with a constant and a class
  method, assigns `TOP502`, and reads both.
- `/return_from_block`, `/return_from_for`: the two locations of #502;
  `/return_top`: the same with a top-level `return`.
- `/break_next`, `/set_return_from_block`: `next` and `break` in a block,
  and `return` with a value from a block, in `mruby_set_code`.
- `/block_given`: `block_given?` at the top level (`false`).
- `/raise`: `raise` at line 3, for the lines in `error.log`.

A second configuration on the same binary (port 18503) asks the visibility
of a `def` (1.4): `/def_set` defines `helper502b`, and `/def_call` calls
`"x".helper502b` and reads whether `Object.public_instance_methods(false)`
and `Object.private_instance_methods(false)` list it. The same three steps
ran as a plain script (`def h502`) with `mruby/build/host/bin/mruby` of the
`test.sh` build.

The scenario reads names with `Object.const_defined?`, `respond_to?` and
`rescue NameError`, not with `defined?`: mruby evaluates the operand of
`defined?` (`mruby/doc/limitations.md`, "`defined?`"), so `defined?(C502)`
raises `NameError` while the constant does not exist.

The same scenario ran with the prototype binary in each frame (3.4).
Compared with `next`, the responses differ only in `object_id`. The other
differences are in `error.log` and in what nginx writes to stderr at its
startup:

- (c1): none.
- (c2): the extra line of the backtrace (2 (c2)).
- (b): `/set` (a constant assignment) and `/const_lookup` (a class
  definition and constant assignments) do not compile. mruby's compiler
  writes:

  ```text
  INLINE CODE:4:6: dynamic constant assignment
  INLINE CODE:2:10: class definition in method body
  INLINE CODE:3:3: dynamic constant assignment
  INLINE CODE:6:8: dynamic constant assignment
  ```

  The prototype then compiles these two in the top-level frame, so their
  responses are those of `next`. A real change would stop nginx at the
  first of these errors.

### 3.2 The test suite

`sh test.sh` on `next` (acdc82fb1): 221 assertions in
`test/t/ngx_mruby.rb` (99) and the 15 files of `test/t/cases/` (122), all
pass. With the prototype, `ONLY_BUILD_NGX_MRUBY=1 sh test.sh` in each
frame:

| Frame | Assertions | Failed | Note |
|---|---|---|---|
| Unset (the top level, as on `next`) | 221 | 0 | Run twice, before and after the fallback below was added |
| (b) method | 221 | 0 | 12 pieces of code fell back to the top-level frame (2 (b)) |
| (c1) lambda flag | 221 | 0 | |
| (c2) wrapper lambda | 221 | 1 | `ngx_mruby - backtrace log`: expected 3, actual 4 |

`test.sh` stops after `test/t/ngx_mruby.rb` fails, so for (c2) the case
files also ran from a copy of `test.sh` that goes on after a failure.
Without the fallback, (b) would stop nginx at its startup, and no assertion
would run. The suite has no stream test of a `return` in a block, and the
prototype changes only the HTTP module. Five stream tests still depend on
(b): they fetch `/mruby` through the stream proxies, which runs
`unified_hello.rb` (2 (b)).

### 3.3 The perf lane

`sh test/perf/compare.sh build_perf/base-src` in the container, with
`build_perf/base-src` made by `git archive origin/next` (acdc82fb1) and the
head the same commit with the prototype applied; the lane is that of
acdc82fb1. The frame of the head is chosen with `NGX_MRUBY_PROTO_FRAME` when
nginx compiles the code; the base ignores the variable. The first run built
both trees and measured the head with the variable unset. The other three
measured the same two builds again (`ONLY_RUN=1`) with the variable set,
for base and head alike. The handler code of every scenario compiles in
each frame: none of it assigns a constant or defines a class (the init code
of the agent proxy scenarios does, and it keeps the top-level frame). The
numbers are those of aarch64; the CI runner (x86_64) measures other
absolute numbers ("Thresholds and calibration" in `docs/test/README.md`).
The header lines are the same in the four reports:

```text
perf: N=20000 WARMUP=2000; Ir per request of nginx; WARN from 3.0%, FAIL from 5.0% on the number without GC
perf: gems: 12 in both builds, 0 at different commits, 0 only in base, 0 only in head
```

Ir per request without GC, base → head (change); `ruby_calls` is the
number of runs of handler code per request (calls of `ngx_mrb_start_fiber`),
which is 1 in every scenario that runs Ruby except `ruby_call_10` (10) and
0 in the three `proxy_*` scenarios:

| Scenario | Unset (the top-level frame) | (c1) lambda flag | (b) method | (c2) wrapper lambda |
|---|---|---|---|---|
| `hello` | 11069 → 11070 (+0.01%) | 11071 → 11070 (-0.01%) | 11070 → 11178 (+0.97%) | 11070 → 12607 (+13.88%, `FAIL`) |
| `headers` | 26804 → 26804 (-0.00%) | 26804 → 26804 (-0.00%) | 26804 → 26933 (+0.48%) | 26804 → 28029 (+4.57%, `WARN`) |
| `var` | 21911 → 21911 (+0.00%) | 21912 → 21912 (+0.00%) | 21912 → 22110 (+0.90%) | 21912 → 23313 (+6.39%, `FAIL`) |
| `filter` | 13361 → 13362 (+0.01%) | 14192 → 14192 (+0.00%) | 14192 → 14287 (+0.67%) | 14192 → 15297 (+7.79%, `FAIL`) |
| `sleep` | 14804 → 14801 (-0.02%) | 14804 → 14805 (+0.00%) | 14805 → 14759 (-0.31%) | 14803 → 16078 (+8.61%, `FAIL`) |
| `sub_request` | 44788 → 44789 (+0.00%) | 44787 → 44789 (+0.00%) | 44787 → 44707 (-0.18%) | 44736 → 46009 (+2.85%) |
| `file` | 13363 → 13363 (+0.00%) | 13363 → 13363 (-0.00%) | 13363 → 13479 (+0.87%) | 13363 → 14742 (+10.32%, `FAIL`) |
| `proxy_plain_2k` | 21952 → 21952 (+0.00%) | 21952 → 21952 (+0.00%) | 21952 → 21970 (+0.08%) | 21952 → 21970 (+0.08%) |
| `proxy_plain_64k` | 22262 → 22261 (-0.00%) | 22262 → 22262 (+0.00%) | 22261 → 22279 (+0.08%) | 22262 → 22280 (+0.08%) |
| `proxy_stream_plain_50` | 54281 → 54278 (-0.01%) | 54329 → 54324 (-0.01%) | 54336 → 54335 (-0.00%) | 54331 → 54339 (+0.01%) |
| `auth` | 45258 → 45258 (-0.00%) | 45258 → 45257 (-0.00%) | 45258 → 45446 (+0.42%) | 45258 → 46367 (+2.45%) |
| `route_json_2k` | 104050 → 104050 (+0.00%) | 104049 → 104049 (-0.00%) | 104049 → 104196 (+0.14%) | 104049 → 105990 (+1.86%) |
| `ruby_call_1` | 10801 → 10802 (+0.01%) | 10801 → 10803 (+0.01%) | 10801 → 10962 (+1.49%) | 10801 → 11876 (+9.95%, `FAIL`) |
| `ruby_call_10` | 35491 → 35500 (+0.03%) | 35491 → 35501 (+0.03%) | 35491 → 36111 (+1.75%) | 35490 → 47530 (+33.92%, `FAIL`) |

The `compare.sh` runs of the unset, (c1) and (b) frames exited with 0, that
of (c2) with 1 (its `FAIL` rows). What the numbers say:

- Unset: the prototype with the top-level frame is within 0.03% of the
  base. The largest change, `ruby_call_10` at +9 Ir per request, does not
  come from a frame: the unset run uses none, and (c1) shows the same +10.
  It comes with the prototype's build; which part of it was not
  investigated.
- (c1): no change beyond that of the unset run. Marking the proc as a
  lambda costs nothing per run.
- (b): from -80 to +198 Ir per request where Ruby runs, all `ok`; about +62
  per run in `ruby_call_10` (+620 for ten runs). By function (self Ir per
  request, head minus base, from `callgrind_annotate` of a second run of
  `hello` and `ruby_call_10`, which repeated +0.97% and +1.75%): in `hello`,
  `mrb_vm_exec` +42, `_int_malloc` +52 and `unlink_chunk` +18, with
  `incremental_sweep_phase` -64; in `ruby_call_10`, `mrb_vm_exec` +420 (42
  per run) and `_int_malloc` +143.
- (c2): from +1,075 to +1,941 Ir per run of handler code (`ruby_call_1`
  and `route_json_2k`); `ruby_call_10` +12,040 for ten runs (1,204 per
  run), `hello` +1,537. In `hello` the self Ir per request grows by 1,723
  with the GC: `_int_malloc` +519, `mrb_vm_exec` +315, `_int_free` +153,
  `unlink_chunk` +128, `mrb_obj_alloc` +117, `incremental_sweep_phase`
  +116, `mrb_closure_new` +94, and `_int_realloc` with `realloc` +115: the
  lambda, the environment that it captures, the call, and the collection of
  both.
  By AGENTS.md "Design principles", its seven `FAIL` rows and its `WARN`
  row would hold a merge until the owner accepts them.
- The `proxy_*` scenarios run no Ruby; the two `proxy_plain_*` moved by
  +18 Ir (+0.08%) in (b) and (c2), where the code of the other locations of
  the configuration is compiled differently. The comparison does not
  attribute these 18 instructions to a function.
- Between the runs, the base of `filter` measured 13361 Ir per request
  without GC in the first run and 14192 in the three runs with the
  variable set, and each other scenario of the base stayed within 0.1%.
  Base and head of one run always had the same environment, so the change
  that the table shows compares builds under equal conditions; the cause of
  the 6% in the base of `filter` was not investigated.

### 3.4 The prototype

The prototype is not in this pull request; its diff against `next` at
acdc82fb1 is in a comment of the pull request that adds this proposal. It
changes `src/http/ngx_http_mruby_module.c` (170
lines added, 3 removed) and `src/http/ngx_http_mruby_module.h` (one field,
`frame`, in `ngx_mrb_code_t`); the stream module is unchanged. Most of it
exists only for the measurement:

- the choice of the frame with `NGX_MRUBY_PROTO_FRAME` (read with `getenv`
  when nginx compiles the code), and the rule that only request handlers,
  filters and `mruby_set` get it, not init, init_worker, exit_worker,
  server configuration and SSL handshake code;
- the fallback that compiles code in the top-level frame when it does not
  compile in the chosen one, and reports it on stderr, so that one run of
  `test.sh` lists all such code.

The parts that a real change would keep: for (c1), setting
`MRB_PROC_STRICT` on the proc (one line); for (b) and (c2), compiling the
code with a prefix and a suffix (a file is read into a buffer first; about
40 lines); and for (b), making the proc of the method body (eight lines).
Two limits of the wrapping that the prototype does not handle: a file that
contains `__END__` loses the suffix, and a `=begin` on the first line of the
code stops being a comment.

## 4. Recommendation and what the owner decides

Recommendation: **(a), keep the top-level frame** in v3, add the regression
test of #502 to `next`, and on `master` document how to write such a handler
in 2.x. The reasons:

- On `next`, #502 is fixed by mruby 4.0.0 (1.3). None of the frames is
  needed for it.
- (b) makes `nginx -t` refuse every configuration whose handler code
  assigns a constant or defines a class: the first example of the install
  guide, the Rack-style handler, and 19 assertions of the suite. It gives
  nothing in return on `next`, and it would not fix `master`.
- (c1) changes nothing that a script can observe on mruby 4.0.0 and would
  not fix `master` either: code without an effect.
- (c2) is the only form that would also fix `master`. There it would
  change the backtrace of every exception and add 1,075 to 1,941
  instructions to every run of handler code (`hello` +13.88% in the perf
  lane of `next`), which the 2.x policy (compatibility first, stability and
  safety fixes) does not call for when the docs can describe the two ways
  around it. On `next` it adds the same cost for nothing.
- None of the options changes what handler code shares between requests
  (`self`, its instance variables, constants, globals): that comes from the
  one `mrb_state` per worker and from `self` being `main`, not from the
  frame (1.4).

The question for the owner: keep the top-level frame for handler code in v3
(option (a): the regression test on `next`, a note in the 2.x docs on
`master`, then close #502), or run handler code in a method frame (b) or a
lambda frame (c1 or c2)?

## 5. Status and steps

- This proposal changes only docs. Section 7 of the v3 plan records the
  owner's decision (item 14). The owner answered (a), and the three steps
  for (a) below are done.
- After an answer of (a):
  1. A pull request to `next` (#584): a fragment and a case file with the two
     locations of #502 and the assertions of a2ikm/ngx_mruby#2, and the
     `mruby_set_code` form of 3.1. The test passes on `next`, so it needs
     no fix commit; the pull request cites the triage on `master` for the
     500 that the same locations answer with mruby 3.3.0. The same pull
     request adds the entry of this change to `docs/releases/v3.0.0.md`
     and `docs/releases/v3.0.0.ja.md`: it came with #561, and a script can
     observe it (on 2.x, a `return` in a block or a `for` body of handler
     code answers 500 with `LocalJumpError`; on 3.0.0 it ends the handler).
     The entry "`yield` with keyword arguments to a block with keyword
     parameters works (#561)" is the model.
  2. A pull request to `master` (#586): a note in
     `docs/class_and_method/README.md` that in 2.x a `return` inside a
     block or a `for` body of handler code raises `LocalJumpError` (500),
     how to write it instead, and that v3 accepts it. It documents the
     behavior of 2.x and changes none, so it adds no release notes entry.
     On `next`, that paragraph and the paragraph of #584 are one text for
     3.0.0 and 2.x (#590).
  3. Close #502 when both are merged: #502 was closed on 2026-10-19,
     after #586.
- After another answer: a pull request to `next` with the chosen frame for
  HTTP and stream, the test of step 1, the changes of the tests that 2 (b)
  or 2 (c2) lists (with the owner's approval, AGENTS.md "Writing tests"),
  the docs, a release notes entry and the perf comparison.
- Not in this proposal: the texts of `README.md` and `docs/README.md` that
  said the global variables table is freed between scripts (1.4). #592
  (`master`) and #623 (`next`) replaced them.

## Sources

- #502 and [its triage comment](https://github.com/matsumotory/ngx_mruby/issues/502#issuecomment-5977615799);
  a2ikm/ngx_mruby#2 (the tests of the two locations).
- `src/http/ngx_http_mruby_module.c`, `src/http/ngx_http_mruby_async.c`,
  `src/http/ngx_http_mruby_request.c` and
  `src/stream/ngx_stream_mruby_async.c` on `next` at acdc82fb1.
- mruby 4.0.0 as vendored on `next`: `mruby/src/vm.c` (`top_proc`,
  `OP_RETURN_BLK`), `mruby/mrbgems/mruby-fiber/src/fiber.c`,
  `mruby/include/mruby.h`, `mruby/doc/limitations.md`. mruby 3.3.0 as
  vendored on `master` at 0a1e8acb3: `mruby/src/vm.c`.
- mruby/mruby@682583a609 and mruby/mruby#6412, read with the GitHub API on
  2026-10-15.
- `docs/test/README.md` on `next`, "Performance comparison with callgrind".
