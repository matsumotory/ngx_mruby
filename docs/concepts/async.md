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
source: src/http/ngx_http_mruby_async.c 187-239 241-314 316-348 363-410
source: src/http/ngx_http_mruby_module.c 1061-1074
source: src/http/ngx_http_mruby_core.h 30-35
at: 0c72e3970 2026-10-19
call: An access handler's code calls `Nginx::Async.sleep(500)` in its fiber
timer: `__sleep` adds a timer of 500 ms to nginx's event loop, and `Fiber.yield` suspends the fiber
done: The handler returns `NGX_DONE`: nginx keeps the request and leaves the handler
serve: The worker serves its other connections while the timer runs
fire: The timer fires: `ngx_mrb_timer_handler` resumes the fiber
resume: The code goes on after `sleep`; when it ends, the request goes on with the next handler, or nginx ends it with the handler's result
```

- ngx_mruby runs the code of each handler in a fiber of mruby
  (`ngx_mrb_start_fiber`). `Nginx::Async.sleep` arms an nginx timer and
  yields the fiber; while it is suspended, the handler has returned
  `NGX_DONE`, and the worker serves other connections.
- When the timer fires, `ngx_mrb_timer_handler` resumes the fiber with
  the request that it belongs to. If the code ends, ngx_mruby gives nginx
  the result of the handler: the next handler of the phase runs for
  `Nginx::DECLINED`, and nginx ends the request with any other result.
- `Nginx::Async::HTTP.sub_request` works in the same way: it starts an
  nginx subrequest and yields, and nginx resumes the fiber when the
  subrequest has finished.
- nginx resumes the handler only in `mruby_set` and the post-read,
  server rewrite, rewrite and access handlers. While one of them waits,
  ngx_mruby returns `NGX_DONE` to nginx, or `NGX_AGAIN` while a subrequest
  goes on (`ngx_http_mruby_module.c` 1066 to 1074). In a content handler,
  `Nginx::Async.sleep` does not raise, but nginx does not wait for the
  handler: the request ends at the sleep without a response. In
  `mruby_set`, `Nginx::Async::HTTP.sub_request` does not hold the request:
  nginx goes on with the content phase without waiting for the variable.
  In the header and body filters and the log handler, both methods raise
  a `RuntimeError` (the "Known limitations" of
  [the 2.7.1 release notes](../releases/v2.7.1.md#known-limitations), and
  [Nginx::Async#sleep](../class_and_method/README.md#nginxasyncsleepmsec)).
- Code that waits in `sleep` of mruby-sleep, a socket of mruby-socket, a
  file, a shell command or a Redis call blocks the worker for that time
  ([Trust boundary](../README.md#trust-boundary)).

[Nginx::Async](../class_and_method/README.md#nginxasync-class) in the
Ruby reference describes both methods.
