/*
// ngx_mruby_upstream.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/*
// The checks, the parse and the per-peer storage that Nginx::Upstream#server=
// (src/http/ngx_http_mruby_upstream.c) and
// Nginx::Stream::Connection#upstream_server=
// (src/stream/ngx_stream_mruby_connection.c) share. See ngx_mruby_upstream.h.
*/

#include "ngx_mruby_upstream.h"

#include <mruby/string.h>

void ngx_mrb_upstream_check_server(mrb_state *mrb, mrb_value server)
{
  if (RSTRING_LEN(server) <= 0 || (size_t)RSTRING_LEN(server) >= NGX_MRB_UPSTREAM_SERVER_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid upstream server (empty or too long)");
  }
  if (ngx_strlchr((u_char *)RSTRING_PTR(server), (u_char *)RSTRING_END(server), '\0') != NULL) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid upstream server (contains a NUL byte)");
  }
}

ngx_int_t ngx_mrb_upstream_parse_server(mrb_state *mrb, ngx_pool_t *pool, mrb_value server, in_port_t default_port,
                                        ngx_url_t *u)
{
  u_char *serverp;

  serverp = ngx_palloc(pool, RSTRING_LEN(server) + 1);
  if (serverp == NULL) {
    return NGX_ERROR;
  }
  ngx_cpystrn(serverp, (u_char *)RSTRING_PTR(server), RSTRING_LEN(server) + 1);

  ngx_memzero(u, sizeof(ngx_url_t));
  u->url.data = serverp;
  u->url.len = RSTRING_LEN(server);
  u->default_port = default_port;
  u->no_resolve = 1;

  if (ngx_parse_url(pool, u) != NGX_OK) {
    if (u->err) {
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "%S in upstream %S", mrb_str_new_cstr(mrb, u->err), server);
    }
    mrb_raisef(mrb, E_RUNTIME_ERROR, "could not parse upstream server %S", server);
  }
  // With no_resolve, nginx accepts a host name and gives it no address.
  if (u->naddrs == 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "upstream server %S is not an IP address or a unix: path", server);
  }

  return NGX_OK;
}

/* The array of stores lives in the cycle pool and is reused across the
 * requests and connections of one cycle. On reload, the cycle pool is freed;
 * the pool cleanup below then resets these pointers so the next cycle starts
 * fresh, even when the new cycle's pool happens to be allocated at the
 * address of the old one. */
static ngx_array_t *ngx_mrb_upstream_server_stores;
static ngx_pool_t *ngx_mrb_upstream_server_stores_pool;

static void ngx_mrb_upstream_server_stores_cleanup(void *data)
{
  (void)data;
  ngx_mrb_upstream_server_stores = NULL;
  ngx_mrb_upstream_server_stores_pool = NULL;
}

static ngx_mrb_upstream_server_store_t *ngx_mrb_upstream_server_store(void *peer)
{
  ngx_mrb_upstream_server_store_t **elts, *store;
  ngx_uint_t i;

  if (ngx_mrb_upstream_server_stores == NULL ||
      ngx_mrb_upstream_server_stores_pool != ngx_cycle->pool) {
    ngx_pool_cleanup_t *cln;

    ngx_mrb_upstream_server_stores =
        ngx_array_create(ngx_cycle->pool, 4, sizeof(ngx_mrb_upstream_server_store_t *));
    if (ngx_mrb_upstream_server_stores == NULL) {
      return NULL;
    }
    cln = ngx_pool_cleanup_add(ngx_cycle->pool, 0);
    if (cln == NULL) {
      ngx_mrb_upstream_server_stores = NULL;
      return NULL;
    }
    cln->handler = ngx_mrb_upstream_server_stores_cleanup;
    cln->data = NULL;
    ngx_mrb_upstream_server_stores_pool = ngx_cycle->pool;
  }

  elts = ngx_mrb_upstream_server_stores->elts;
  for (i = 0; i < ngx_mrb_upstream_server_stores->nelts; i++) {
    if (elts[i]->peer == peer) {
      return elts[i];
    }
  }

  store = ngx_palloc(ngx_cycle->pool, sizeof(ngx_mrb_upstream_server_store_t));
  if (store == NULL) {
    return NULL;
  }
  store->peer = peer;

  elts = ngx_array_push(ngx_mrb_upstream_server_stores);
  if (elts == NULL) {
    return NULL;
  }
  *elts = store;

  return store;
}

ngx_mrb_upstream_server_store_t *ngx_mrb_upstream_server_save(void *peer, ngx_url_t *u)
{
  ngx_mrb_upstream_server_store_t *store;

  store = ngx_mrb_upstream_server_store(peer);
  if (store == NULL) {
    return NULL;
  }
  ngx_memcpy(store->name, u->url.data, u->url.len);
  ngx_memcpy(&store->sockaddr, u->addrs[0].sockaddr, u->addrs[0].socklen);

  return store;
}
