# Filters

nginx sends the header and the body of a response through two chains of
filters, whichever handler or upstream produced the response. ngx_mruby
adds one filter to each chain: `mruby_output_header_filter` (and its form
`_code`) runs Ruby on the header, and `mruby_output_body_filter` (and
`_code`) on the body. ngx_mruby adds its header filter when the
configuration has either directive, and its body filter when it has a
body filter.

```diagram
filter-chain
caption: nginx's header filters and body filters in the order in which nginx calls them, with the filters of ngx_mruby, and what each filter of ngx_mruby receives.
source: src/http/ngx_http_mruby_module.c 591-595 1676-1677 1955-1965 2041-2054 2085-2122 2135-2154
source: config.in 48-69
nginx: 1.31.6 auto/modules 165-187 386-427 1494-1495
nginx: 1.31.6 auto/module 23-30
at: 0c72e3970 2026-10-19
h-header: Header filters
hn: nginx's not-modified header filter
hm: `mruby_output_header_filter`: the status and the headers; with a body filter, the header waits for it
ho: the header filters of nginx's other modules
hw: nginx writes the header
h-body: Body filters
bn: nginx's range and copy body filters
bm: `mruby_output_body_filter`: the whole body, with `Content-Length`; any other body passes unread
bo: the body filters of nginx's other modules
bw: nginx's write filter sends the body
```

- nginx calls the filters of each chain from the top. ngx_mruby's filters
  come after nginx's not-modified header filter and its range and copy
  body filters, and before the filters of nginx's other modules, such as
  `gzip` and the chunked filter, so a filter of ngx_mruby sees the
  response before nginx compresses or chunks it. nginx builds the chains
  in the order of its modules (`auto/modules`), where ngx_mruby stands
  after nginx's own filter modules and before the copy, range body,
  not-modified and slice filters, and each filter goes in front of those
  before it. The slice filter exists in a build with
  `--with-http_slice_module`.
- The header filter reads and changes the status and the headers through
  `Nginx::Request` and `Nginx::Headers_out`. It runs before the body has
  been read: there `Nginx::Filter#body` returns an empty string.
- The body filter needs the length of the response. For a response with
  `Content-Length`, ngx_mruby collects the whole body into one buffer,
  runs the script once with it in `Nginx::Filter#body`, and sends what the
  script puts into `Nginx::Filter#body=`. A response without
  `Content-Length`, such as a chunked response of an upstream, passes the
  filter unread, and ngx_mruby logs that at the `notice` level.
- When a location has a body filter, ngx_mruby holds the header back
  until the body filter has run, so that `Content-Length` is the length of
  the new body.
- Neither filter can wait: `Nginx::Async.sleep` and
  `Nginx::Async::HTTP.sub_request` raise a `RuntimeError` there, and
  `Nginx.rputs` and `Nginx.echo` cannot be used.

The guide [Change a response body](../guides/body-filter.md) has a
sample of both filters that CI runs. [The directive reference](../directives/README.md#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code)
gives their syntax.
