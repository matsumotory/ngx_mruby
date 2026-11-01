# Waiting without blocking

A worker of nginx serves many connections at once from one event loop. A
handler that waits in a blocking call, such as `sleep` or a socket read,
stops the whole worker. `Nginx::Async.sleep` and
`Nginx::Async::HTTP.sub_request` wait through nginx instead: the Ruby code
of the handler runs in a fiber, which yields to nginx and is resumed from
nginx's event loop.

```diagram
async-sleep
caption: What happens when an access handler calls `Nginx::Async.sleep`, from the call until the handler's code goes on.
source: mrbgems/ngx_mruby_mrblib/mrblib/mrb_nginx.rb 100-106
source: src/http/ngx_http_mruby_async.c 415-430 503-591 615-630 659-693
source: src/http/ngx_http_mruby_module.c 942-959 1099-1132
source: src/http/ngx_http_mruby_core.h 30-35
at: 819212d88 2026-11-01
call: An access handler's code calls `Nginx::Async.sleep(500)` in its fiber
timer: `__sleep` adds a timer of 500 ms to nginx's event loop, and `Fiber.yield` suspends the fiber
done: The handler returns `NGX_DONE`: nginx keeps the request and leaves the handler
serve: The worker serves its other connections while the timer runs
fire: The timer fires: `ngx_mrb_timer_handler` marks the fiber ready to resume and posts the request
resume: nginx calls the handler again, which resumes the fiber; when the code ends, the access phase handles its result as without the sleep
```

- ngx_mruby runs the code of each handler in a fiber of mruby
  (`ngx_mrb_start_fiber`). `Nginx::Async.sleep` arms an nginx timer and
  yields the fiber; while it is suspended, the handler has returned
  `NGX_DONE`, and the worker serves other connections.
- When the timer fires, `ngx_mrb_timer_handler` marks the fiber ready to
  resume and posts the request, and nginx calls the handler again. The
  handler resumes the fiber instead of starting the code. When the code
  ends, the handler returns its result to the phase as a handler that did
  not wait does: an access handler without a result lets nginx go on with
  the next access handler, and a 403 under `satisfy any` lets nginx try
  the next one. While the fiber waits, nginx does not run the code again.
- An `mruby_set` handler runs inside the script of the rewrite module, so
  nginx does not call it again: ngx_mruby resumes its fiber, sets the
  variable when the code ends, and runs the phases from the next handler.
- `Nginx::Async::HTTP.sub_request` starts an nginx subrequest and yields.
  When the subrequest ends, nginx wakes the request, calls the handler
  again, and the handler resumes the fiber, to which `sub_request` returns
  the response.
- `mruby_set` and the post-read, server rewrite, rewrite, access and
  content handlers can wait and resume. A suspended handler returns
  `NGX_DONE`.
- nginx keeps the request of a content handler while `Nginx::Async.sleep`
  waits, since the 2.7.3 changes, which 3.x includes. The response or the
  returned status of the code completes the request. Up to 2.7.2, the
  request ended at the sleep without a response. Since 3.0.0,
  `Nginx.redirect` takes effect when the calling handler ends, so the
  handlers of its target can wait as well.
- A content handler can wait for `Nginx::Async::HTTP.sub_request`, also
  after `Nginx::Async.sleep`, since 3.0.0; 2.7.3 raises `RuntimeError`
  there. In `mruby_set`, `Nginx::Async::HTTP.sub_request` raises
  `RuntimeError` since 3.0.0, because nginx does not wait for a subrequest
  of the rewrite script; 2.x went on to the content phase without waiting
  for the variable. In header/body filters and the log handler, both async
  methods raise `RuntimeError`.
  See [the 2.7.3 behavior changes](../releases/v2.7.3.md) and
  [Nginx::Async#sleep](../class_and_method/README.md#nginxasyncsleepmsec).
- `Nginx::Stream::Async.sleep` waits in the same way in the code of a
  stream session (`mruby_stream`, `mruby_stream_code`): when the timer
  fires, nginx calls the handler of the access phase again, the handler
  resumes the fiber, and the session goes on by the result of the code. A
  session runs its code once: a datagram of a UDP session or bytes from the
  client of a TCP session that arrive during the wait do not start it again.
- When the client closes the connection while the code waits, the code goes
  on: nginx does not read from the client of an HTTP/1.x request while the
  handlers run, or from the client of a stream session while its code
  waits, and sees the close when it writes the response or after the code
  resumes. When nginx ends the request or the session during the wait, for
  example when `worker_shutdown_timeout` expires in a worker that shuts
  down, the fiber is not resumed: the code after the wait, an `ensure`
  clause included, does not run. On a reload, the old workers finish the
  waits in flight before they exit.
- Code that waits in `sleep` of mruby-sleep, a socket of mruby-socket, a
  file, a shell command or a Redis call blocks the worker for that time
  ([Trust boundary](../security/trust-boundary.md)).

[Nginx::Async](../class_and_method/README.md#nginxasync-class) in the
Ruby reference describes both methods. How ngx_mruby keeps, resumes and
cancels the fiber of a handler is in
[How a handler waits](../DEVELOPMENT.md#how-a-handler-waits-the-record-of-its-fiber)
for contributors.
