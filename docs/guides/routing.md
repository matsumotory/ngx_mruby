# Route requests to a backend

nginx passes a request to a backend with `proxy_pass`. With
[`mruby_set`](../directives/README.md#mruby_set-and-mruby_set_code), a
Ruby script computes the backend for each request, and `proxy_pass` uses
the variable that the script sets. nginx then connects to the backend and
relays the response; the script runs once per request and returns a
string.

## The sample

The script picks the backend from the request header `X-Tenant`, with a
table of tenants and backend addresses, and backend `a` for a request
without the header or with an unknown tenant. The value of the last line of
the script is the value of `$backend`.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/73-guide-routing.conf
script: test/html/guide_routing.rb
request: test/html/guide_routing.request
response: test/html/guide_routing.response
```

The case also sends a request without `X-Tenant` and expects the answer of
backend `a`, on port 18164.

## What to keep in mind

- `mruby_set` runs in the rewrite phase of the location, before nginx
  connects to the backend ([Request phases](../concepts/request-phases.md)).
  The script reads the request through `Nginx::Request`; it does not see
  the response.
- `proxy_pass` with a variable takes an address as it is. A value that
  names an `upstream` block uses that block; any other host name needs
  nginx's `resolver` directive.
- The request header is client input: the script compares it with the
  keys of its table, so that a client can only reach the backends that the
  table lists ([Trust boundary](../security/trust-boundary.md)).
- Without `cache`, nginx reads the script file for every request. Add
  `cache` to the directive, or use `mruby_set_code`, in production
  ([Caching compile code](../directives/README.md#caching-compile-code)).
