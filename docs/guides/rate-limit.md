# Limit the rate per API key

nginx's `limit_req` counts requests per key in a shared memory zone, which
all workers use, and rejects the requests over the rate. The key is any
nginx variable. A Ruby script computes it with
[`mruby_set`](../directives/README.md#mruby_set-and-mruby_set_code), so
that the limit applies to a value that Ruby derives from the request, such
as an API key, while nginx keeps the counters.

## The sample

The script returns the API key of the header `X-API-Key`, or the client
address for a request without one, so that no request has an empty key:
`limit_req` does not count a request whose key is empty. The zone allows
one request per minute and key. `limit_req_status 429` and
`error_page 429 @limited` give the rejected request the status 429 and a
JSON body.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/75-guide-rate-limit.conf
script: test/html/guide_rate_limit.rb
request: test/html/guide_rate_limit.request
response: test/html/guide_rate_limit.response
```

The case sends the request twice. The first answers 200 with the body
`accepted`; the second, within the same minute, gets the response above.

## What to keep in mind

- `mruby_set` runs in the rewrite phase, and `limit_req` in the preaccess
  phase after it ([Request phases](../concepts/request-phases.md)), so
  the variable has its value when nginx counts the request.
- The counters live in nginx's shared memory zone, not in Ruby. Each
  worker has its own mruby state, and a counter in a Ruby global would
  count the requests of one worker only.
- `limit_req_zone` is a directive of the `http` block; `limit_req` and
  `limit_req_status` go into the `http` block, a `server` or a
  `location`.
