/*
// ngx_http_mruby_upstream.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/* dirty hack to include nginx code. See ngx_http_mruby_upstream.h */
#define NGX_HTTP_MRUBY_UPSTREAM_C

#include "ngx_http_mruby_upstream.h"

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include "../common/ngx_mruby_upstream.h"

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

typedef struct {
  mrb_value upstream;
  ngx_http_upstream_rr_peer_t *target;
  ngx_http_upstream_rr_peers_t *peers;
  ngx_http_upstream_srv_conf_t *us;
} ngx_mruby_upstream_context;

static void ngx_mrb_upstream_context_free(mrb_state *mrb, void *p)
{
  ngx_mruby_upstream_context *ctx = p;
  mrb_free(mrb, ctx);
}

static const struct mrb_data_type ngx_mrb_upstream_context_type = {
    "ngx_mrb_upstream_context",
    ngx_mrb_upstream_context_free,
};

static mrb_value ngx_mrb_upstream_init(mrb_state *mrb, mrb_value self)
{
  ngx_uint_t i;
  mrb_value upstream;
  ngx_mruby_upstream_context *ctx;
  ngx_http_upstream_main_conf_t *umcf;
  ngx_http_upstream_srv_conf_t **usp;
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "S", &upstream);

  ctx = (ngx_mruby_upstream_context *)DATA_PTR(self);
  if (ctx) {
    mrb_free(mrb, ctx);
  }
  mrb_data_init(self, NULL, &ngx_mrb_upstream_context_type);

  ctx = (ngx_mruby_upstream_context *)mrb_malloc(mrb, sizeof(ngx_mruby_upstream_context));

  ctx->upstream = upstream;
  ctx->target = NULL;
  ctx->peers = NULL;
  ctx->us = NULL;

  umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
  usp = umcf->upstreams.elts;

  for (i = 0; i < umcf->upstreams.nelts; i++) {
    // the whole name, case-insensitively, as nginx compares upstream names
    if (usp[i]->host.len == (size_t)RSTRING_LEN(upstream) &&
        ngx_strncasecmp(usp[i]->host.data, (u_char *)RSTRING_PTR(upstream), RSTRING_LEN(upstream)) == 0) {
      ctx->us = usp[i];
      ctx->peers = usp[i]->peer.data;
      if (ctx->peers->number > 1) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "don't support multiple server config");
      }
      ctx->target = ctx->peers->peer;
      break;
    }
  }

  mrb_data_init(self, ctx, &ngx_mrb_upstream_context_type);

  if (ctx->us == NULL || ctx->peers == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%S not found upstream config", upstream);
  }

  if (ctx->target == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "not found server config in upstream");
  }

  return self;
}

static mrb_value ngx_mrb_upstream_set_cache(mrb_state *mrb, mrb_value self)
{
  mrb_int cache;
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  __ngx_http_upstream_keepalive_srv_conf_t *kcf;

  kcf = ngx_http_conf_upstream_srv_conf(ctx->us, __ngx_http_upstream_keepalive_module);

  mrb_get_args(mrb, "i", &cache);

  if (cache < 2) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid upstream_cache: set value > 1");
  }

  kcf->max_cached = cache;
  return mrb_fixnum_value(cache);
}

static mrb_value ngx_mrb_upstream_get_cache(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  __ngx_http_upstream_keepalive_srv_conf_t *kcf;

  kcf = ngx_http_conf_upstream_srv_conf(ctx->us, __ngx_http_upstream_keepalive_module);

  /* max_cached is 1 by default */

  return mrb_fixnum_value(kcf->max_cached);
}

static mrb_value ngx_mrb_upstream_get_server(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  if (ctx->target == NULL) {
    return mrb_nil_value();
  }
  return mrb_str_new(mrb, (char *)ctx->target->name.data, ctx->target->name.len);
}

// The checks, the parse and the storage of the peer are in
// src/common/ngx_mruby_upstream.c, shared with
// Nginx::Stream::Connection#upstream_server=. This setter keeps the check of
// an upstream with a zone, the port 80 of a string without one, the locks of
// the peer, and nil when an allocation fails.
static mrb_value ngx_mrb_upstream_set_server(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  ngx_url_t u;
  mrb_value server;
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  ngx_mrb_upstream_server_store_t *store;

  mrb_get_args(mrb, "S", &server);

  ngx_mrb_upstream_check_server(mrb, server);

#if (NGX_HTTP_UPSTREAM_ZONE)
  // The peers of an upstream with a zone are in shared memory that every
  // worker reads, and the store below is in the memory of this worker.
  if (ctx->peers->shpool) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Nginx::Upstream#server= does not support an upstream with a zone");
  }
#endif

  if (ngx_mrb_upstream_parse_server(mrb, r->pool, server, 80, &u) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    return mrb_nil_value();
  }

  /* Copy the name and the sockaddr into worker-lifetime storage so the
   * shared peer never points into the freed request pool (use-after-free). */
  store = ngx_mrb_upstream_server_save(ctx->target, &u);
  if (store == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    return mrb_nil_value();
  }

  ngx_http_upstream_rr_peers_rlock(ctx->peers);
  ngx_http_upstream_rr_peer_lock(ctx->peers, ctx->target);
  ctx->target->name.data = store->name;
  ctx->target->name.len = u.url.len;
  ctx->target->server.data = store->name;
  ctx->target->server.len = u.url.len;
  ctx->target->sockaddr = &store->sockaddr.sockaddr;
  ctx->target->socklen = u.addrs[0].socklen;
  ngx_http_upstream_rr_peer_unlock(ctx->peers, ctx->target);
  ngx_http_upstream_rr_peers_unlock(ctx->peers);

  return server;
}

void ngx_mrb_upstream_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_upstream;

  class_upstream = mrb_define_class_under(mrb, class, "Upstream", mrb->object_class);
  MRB_SET_INSTANCE_TT(class_upstream, MRB_TT_DATA);
  mrb_define_method(mrb, class_upstream, "initialize", ngx_mrb_upstream_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "keepalive_cache", ngx_mrb_upstream_get_cache, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_upstream, "keepalive_cache=", ngx_mrb_upstream_set_cache, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "server", ngx_mrb_upstream_get_server, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_upstream, "server=", ngx_mrb_upstream_set_server, MRB_ARGS_REQ(1));
}
