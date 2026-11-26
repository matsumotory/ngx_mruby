# Content-Length through Nginx::Headers_out

Status: implemented in [#874](https://github.com/matsumotory/ngx_mruby/pull/874),
merged into `next` on 2026-11-26 (`3747aa37f`); sections 2 to 4 shipped, with
the tests of `test/t/cases/content_length.rb`, and the published advisory is
GHSA-2cf7-qh69-j29q. This proposal makes `Content-Length` one of
nginx's own response fields in `Nginx::Headers_out`, as `Content-Type`,
`Location`, `Date` and `Server` already are, so that a response carries one
`Content-Length`, the length nginx frames the body by.

## 1. Current behavior

`Nginx::Headers_out#[]=` with `Content-Length` added a response header list
entry and did not touch `r->headers_out.content_length_n` or
`r->headers_out.content_length`. nginx writes its own `Content-Length` from
`content_length_n` (the length of the output of `Nginx.rputs`, or of a proxied
or static body), and then writes every list entry, so a `Content-Length` that a
script set was sent as a second line next to nginx's own. `#[]` read only a
line a script had added, and `#delete` removed only such a line, never nginx's
length.

A response with two `Content-Length` lines whose values differ has no single
body length: nginx as a client (`proxy_pass`) answers 502 for such a response,
and browsers reject it. So the second line is never useful; a script that
sets `Content-Length` wants nginx to send that length, as it does in other
nginx modules.

### OpenResty

OpenResty's `ngx.header["Content-Length"] = v` (lua-nginx-module) and
`more_set_headers` (headers-more-nginx-module) parse the value, set
`content_length_n` and point `r->headers_out.content_length` at one entry: one
line. Reading returns `content_length_n` when there is no entry and the length
is known, so a header filter reads the length of a proxied or static response.
`Content-Length = nil` clears the length. Operators coming from OpenResty
expect this.

ngx_mruby differs from OpenResty in one way that it can use: `Nginx.rputs`
buffers the output of a handler, so ngx_mruby knows the length of that output
when it sends the header, while ngx_lua streams and trusts the script's value.

## 2. Design (Option A)

`Content-Length` becomes nginx's own field:

- `#[]=` parses a non-negative decimal (`ngx_atoof`) and sets one list entry
  that `r->headers_out.content_length` points at. A value that is not a
  non-negative decimal, or an Array of more than one element, raises
  `ArgumentError`. `#[]= nil` and `#delete` clear the length.
- `#[]` returns the value set, or `content_length_n` as a String when it is
  at least 0 and no entry is set (as OpenResty does), or nil.
- `#[]=` does not change `content_length_n` itself. Before the response
  headers go out, ngx_mruby's header filter reconciles the length a script set
  with the body nginx frames (`content_length_n`): when they are equal the one
  entry is kept; when they differ, or the body's length is not known, the
  script's entry is dropped so nginx sends its own `Content-Length` from
  `content_length_n`, or sends the response chunked when that length is -1,
  and a line at the `warn` level names the difference. `#delete` makes
  `content_length_n` -1, so the response is chunked (HTTP/1.1) or
  close-delimited (HTTP/1.0). The reconciliation runs for every response where
  a script touched `Content-Length`, in any phase, so a value set in a content
  handler, a phase handler before a static or proxied body, or an output
  header filter is reconciled the same way. A 204 or 304, which nginx sends
  with no `Content-Length`, drops the entry.

ngx_mruby can reconcile because `Nginx.rputs` buffers the output (so the
output's length is known) and because its header filter runs before nginx's
own header and chunked filters. The result is that the one `Content-Length`
always matches the body, which is stronger than trusting the script's value
as OpenResty does: a value that does not match the body is corrected to the
real length (or the response is chunked), not sent as given.

A location with an mruby body filter does not reach the reconciliation: the
body filter sets `content_length_n` to the body it produced and clears any
entry (`ngx_mrb_finalize_body_filter`), so the final `Content-Length` is the
new body's length.

## 3. Decisions

- A handler that writes output and sets a different `Content-Length` sends the
  output's length and logs `warn` (the output's length is always correct for
  the bytes that go out).
- A HEAD request to a handler that sets `Content-Length` and writes no output
  sends the value set: a HEAD response states the length the GET body would
  have and carries no body, as nginx's static module does for HEAD.
- A header or phase handler that sets a `Content-Length` which differs from a
  length nginx already knows for a proxied or static response sends the real
  length and logs `warn`; when the length is not known, the response is sent
  chunked. (A value that is not a non-negative decimal raises.)
- A value that is not a non-negative decimal, or an Array of more than one
  element, raises `ArgumentError`.
- 2.x keeps compatibility (see `docs/releases/`): a value set through
  `Nginx::Headers_out` is not sent, and the length cannot be changed this way;
  the full field semantics are a v3 change.

## 4. Tests

`test/t/cases/content_length.rb` with `test/conf/conf.d/76-content-length.conf`
and `test/html/content_length_static.txt` (ports 18096 and 18122): a content
handler that sets a value differing from and equal to its output, a value with
no output, values that raise, `#[]`, a phase handler before a static file, an
output header filter on proxied responses of a known and of an unknown length,
`#delete`, and a 204. Each case asserts the status, the `Content-Length` lines
(the count and the value), `Transfer-Encoding`, the body bytes and, where a
value differs, the `warn` line in `error.log`.
