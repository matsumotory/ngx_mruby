# Concepts

These pages explain how ngx_mruby runs Ruby inside nginx: where in the
processing of a request each handler runs, how the filters see a response,
how a handler waits without blocking the worker, and what lives across
requests.

- [Request phases](request-phases.md): nginx's HTTP phases in order, and
  the ngx_mruby directive that runs Ruby in each of them.
- [Filters](filters.md): where the header filter and the body filter of
  ngx_mruby stand in nginx's filter chains, and what each one receives.
- [Waiting without blocking](async.md): how `Nginx::Async.sleep` and
  `Nginx::Async::HTTP.sub_request` give the worker back to nginx.
- [Lifetimes](lifetimes.md): one `mrb_state` per worker, and what a worker
  keeps between requests.
- [Trust boundary](../README.md#trust-boundary): what ngx_mruby trusts,
  what it treats as client input, and what a script is responsible for.
