# Allow TCP connections in Ruby

nginx's stream module proxies TCP connections, and UDP sessions with
`listen ... udp`. In a `server` of the `stream` block,
[`mruby_stream`](../directives/README.md#stream-module-directives) runs a
Ruby script in the access phase of the stream module, once per session,
before nginx connects to the upstream. The script reads the addresses of
the session through `Nginx::Stream::Connection`, and closes the session by
setting `stream_status` to `Nginx::Stream::ABORT`.

## The sample

The script lets the session through only from the addresses of its list.
nginx then proxies the connection to the upstream, here an HTTP server of
the test configuration on port 18168. The request and the response are the
bytes that the client sends and receives over the TCP connection.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/stream/42-guide-tcp.conf
script: test/html/guide_tcp.rb
request: test/html/guide_tcp.request
response: test/html/guide_tcp.response
```

## What to keep in mind

- The stream module runs the script for UDP sessions too; the test suite
  sends TCP only.
- The script runs before nginx reads the client's data, so it decides on
  the addresses and ports of the session, not on what the client sends.
- The `stream` block has its own mruby state, separate from that of the
  `http` block, and its own directives for the code at startup
  (`mruby_stream_init`, `mruby_stream_init_worker`).
