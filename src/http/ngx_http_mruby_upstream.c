/*
// ngx_http_mruby_upstream.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_module.h"

#ifndef NGX_USE_MRUBY_UPSTREAM
#include "ngx_http_mruby_upstream.h"
#else

#include "ngx_http_mruby_request.h"
#include "ngx_http_mruby_upstream.h"

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
    "ngx_mrb_upstream_context", ngx_mrb_upstream_context_free,
};

static mrb_value ngx_mrb_upstream_init(mrb_state *mrb, mrb_value self)
{
  ngx_uint_t i;
  mrb_value upstream;
  ngx_mruby_upstream_context *ctx;
  ngx_http_upstream_main_conf_t *umcf;
  ngx_http_upstream_srv_conf_t **usp;
  ngx_http_request_t *r = ngx_mrb_get_request();

  mrb_get_args(mrb, "o", &upstream);

  ctx = (ngx_mruby_upstream_context *)DATA_PTR(self);
  if (ctx) {
    mrb_free(mrb, ctx);
  }
  DATA_TYPE(self) = &ngx_mrb_upstream_context_type;
  DATA_PTR(self) = NULL;
  ctx = (ngx_mruby_upstream_context *)mrb_malloc(mrb, sizeof(ngx_mruby_upstream_context));

  ctx->upstream = upstream;
  ctx->target = NULL;
  ctx->peers = NULL;
  ctx->us = NULL;

  umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
  usp = umcf->upstreams.elts;

  for (i = 0; i < umcf->upstreams.nelts; i++) {
    if (ngx_strncasecmp(usp[i]->host.data, (u_char *)RSTRING_PTR(upstream), RSTRING_LEN(upstream)) == 0) {
      ctx->us = usp[i];
      ctx->peers = usp[i]->peer.data;
      if (ctx->peers->number > 1) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "don't support multiple server config");
      }
      ctx->target = ctx->peers->peer;
      break;
    }
  }

  DATA_PTR(self) = ctx;

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
  unsigned int cache;
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

static mrb_value ngx_mrb_upstream_set_server(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  ngx_url_t u;
  mrb_value server;
  ngx_http_request_t *r = ngx_mrb_get_request();

  mrb_get_args(mrb, "o", &server);

  ngx_memzero(&u, sizeof(ngx_url_t));
  u.url.data = (u_char *)RSTRING_PTR(server);
  u.url.len = RSTRING_LEN(server);
  u.default_port = 80;
  if (ngx_parse_url(r->pool, &u) != NGX_OK) {
    if (u.err) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "%S in upstream %S", mrb_str_new_cstr(mrb, u.err), server);
    }
  }
  ctx->target->name = u.url;
  ctx->target->server = u.url;
  ctx->target->sockaddr = u.addrs[0].sockaddr;
  ctx->target->socklen = u.addrs[0].socklen;

  return server;
}

void ngx_mrb_upstream_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_upstream;

  class_upstream = mrb_define_class_under(mrb, class, "Upstream", mrb->object_class);
  mrb_define_method(mrb, class_upstream, "initialize", ngx_mrb_upstream_init, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, class_upstream, "keepalive_cache", ngx_mrb_upstream_get_cache, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_upstream, "keepalive_cache=", ngx_mrb_upstream_set_cache, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "server", ngx_mrb_upstream_get_server, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_upstream, "server=", ngx_mrb_upstream_set_server, MRB_ARGS_REQ(1));
}

#endif /* NGX_USE_MRUBY_UPSTREAM */
