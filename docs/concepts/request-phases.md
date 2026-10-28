# Request phases

nginx handles an HTTP request in a fixed order of phases. ngx_mruby adds a
handler to six of them, runs `mruby_set` inside the rewrite module, adds
a header filter and a body filter to nginx's filter chains, and runs a
handler during the TLS handshake. For TCP and UDP, it runs one handler in
the access phase of nginx's stream module.

```diagram
request-phases
caption: nginx's HTTP phases in order, the ngx_mruby directive that runs Ruby in each of them, and the handler for TCP and UDP sessions.
source: src/http/ngx_http_mruby_module.c 431 638-721 1742-1824 1954-1965
source: src/stream/ngx_stream_mruby_module.c 787
nginx: 1.31.6 src/http/ngx_http_core_module.h 111-128
at: 0c72e3970 2026-10-19
h-phase: What nginx does, in order
h-handler: Where ngx_mruby runs Ruby
tls: TLS handshake
tls-h: `mruby_ssl_handshake_handler`
post-read: post-read
post-read-h: `mruby_post_read_handler`
server-rewrite: server rewrite
server-rewrite-h: `mruby_server_rewrite_handler`
server-rewrite-set: `mruby_set`, in the rewrite module
find-config: find config
rewrite: rewrite
rewrite-h: `mruby_rewrite_handler`
rewrite-set: `mruby_set`, in the rewrite module
post-rewrite: post-rewrite, preaccess
access: access
access-h: `mruby_access_handler`
post-access: post-access, precontent
content: content
content-h: `mruby_content_handler`
header-filter: header filters
header-filter-h: `mruby_output_header_filter`
body-filter: body filters
body-filter-h: `mruby_output_body_filter`
log: log
log-h: `mruby_log_handler`
stream: TCP or UDP access
stream-h: `mruby_stream`
```

Each directive in the table takes the path of a Ruby script. Each also has
a form with the suffix `_code`, such as `mruby_access_handler_code`, which
takes the Ruby code itself.

| When it runs | Directive |
|---|---|
| TLS handshake | `mruby_ssl_handshake_handler` |
| post-read phase | `mruby_post_read_handler` |
| server rewrite phase | `mruby_server_rewrite_handler` |
| rewrite phase | `mruby_rewrite_handler` |
| access phase | `mruby_access_handler` |
| content phase | `mruby_content_handler` |
| as the response header goes out | `mruby_output_header_filter` |
| as the response body goes out | `mruby_output_body_filter` |
| log phase | `mruby_log_handler` |
| server rewrite and rewrite phases | `mruby_set` |
| access phase of the stream module | `mruby_stream` |

The TLS handshake comes before nginx reads the request. nginx runs the
find config, post-rewrite, preaccess, post-access and precontent phases
without an ngx_mruby handler. `mruby_set` sets a
variable from Ruby where the rewrite module runs `set`: in the server
rewrite phase for a `mruby_set` in a `server` block, and in the rewrite
phase for one in a `location`. The header filter and the body filter run
while nginx sends a response, whichever phase made it: a content handler,
an upstream, or a `return` or an error of an earlier phase; so they come
before the log phase. In nginx's filter chains, ngx_mruby's filters run
after nginx's not-modified header filter and its range and copy body
filters, and before the filters of nginx's other modules. `mruby_post_read_handler` is accepted in
the `http` and `server` blocks, and `mruby_ssl_handshake_handler` in a
`server` block; the other handlers are also accepted in a `location`.
