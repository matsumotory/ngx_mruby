/*
// ngx_mruby_upstream.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_MRUBY_UPSTREAM_H
#define NGX_MRUBY_UPSTREAM_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>

/*
// The part of Nginx::Upstream#server= (http) and
// Nginx::Stream::Connection#upstream_server= (stream) that does not depend on
// the protocol: the checks of the string, its parse, and the storage that the
// round-robin peer points at afterwards. Each setter keeps what depends on its
// protocol: the check of an upstream with a zone, the assignment to its own
// peer type, the locks of the peer (http), and what it does when an
// allocation fails (http logs and returns nil, stream raises).
//
// A setter calls, in this order:
//
//   ngx_mrb_upstream_check_server(mrb, server);
//   (its own check of an upstream with a zone)
//   if (ngx_mrb_upstream_parse_server(mrb, pool, server, default_port, &u) != NGX_OK) {
//     (allocation failure)
//   }
//   store = ngx_mrb_upstream_server_save(peer, &u);
//   if (store == NULL) {
//     (allocation failure)
//   }
//   (assign store->name, u.url.len, &store->sockaddr.sockaddr and
//    u.addrs[0].socklen to the peer)
*/

/* A server string must be shorter than this, in bytes. */
#define NGX_MRB_UPSTREAM_SERVER_MAX 256

/*
// The storage of one peer, for the worker's life. The round-robin peer lives
// for the worker's life (the configuration pool) and is shared by every
// request or session that uses the upstream, so its name and sockaddr must
// not point into the Ruby string (which the mruby GC may free or move) or the
// pool of the request or the connection (freed when it ends). One store per
// peer is allocated once in the cycle pool and reused, so repeated calls do
// not accumulate. peer is the http or the stream peer, compared only as a
// pointer. Only the non-zone case is handled: the peers of an upstream with a
// zone are in shared memory that every worker reads.
*/
typedef struct {
  void *peer;
  ngx_sockaddr_t sockaddr;
  u_char name[NGX_MRB_UPSTREAM_SERVER_MAX];
} ngx_mrb_upstream_server_store_t;

/*
// Raises ArgumentError when server (a String) is empty, is
// NGX_MRB_UPSTREAM_SERVER_MAX bytes or longer, or holds a NUL byte.
*/
void ngx_mrb_upstream_check_server(mrb_state *mrb, mrb_value server);

/*
// Parses server (a String that passed ngx_mrb_upstream_check_server) into u
// with ngx_parse_url and no_resolve, from a copy in pool. default_port is the
// port of a string without one. Returns NGX_ERROR, before it parses, when the
// copy cannot be allocated, and NGX_OK when u holds at least one address.
// Raises ArgumentError for a string that nginx cannot read as an address and
// for a host name, which no_resolve leaves without an address, and
// RuntimeError when nginx fails while it reads the string.
*/
ngx_int_t ngx_mrb_upstream_parse_server(mrb_state *mrb, ngx_pool_t *pool, mrb_value server, in_port_t default_port,
                                        ngx_url_t *u);

/*
// Finds or makes the store of peer for the current cycle, and copies the
// name of u and its first address into it. Returns NULL when the store
// cannot be allocated.
*/
ngx_mrb_upstream_server_store_t *ngx_mrb_upstream_server_save(void *peer, ngx_url_t *u);

#endif /* NGX_MRUBY_UPSTREAM_H */
