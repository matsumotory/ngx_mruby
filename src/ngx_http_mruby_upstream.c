/*
// ngx_http_mruby_upstream.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_upstream.h"
#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

typedef struct {
  unsigned int cache;
  unsigned int keepalive:1;
  mrb_value hostname;
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
  mrb_value host;
  ngx_mruby_upstream_context *ctx;

  mrb_get_args(mrb, "o", &host);

  ctx = (ngx_mruby_upstream_context *)DATA_PTR(self);
  if (ctx) {
    mrb_free(mrb, ctx);
  }
  DATA_TYPE(self) = &ngx_mrb_upstream_context_type;
  DATA_PTR(self) = NULL;
  ctx = (ngx_mruby_upstream_context *)mrb_malloc(mrb, sizeof(ngx_mruby_upstream_context));

  ctx->hostname = host;
  ctx->cache = 0;
  ctx->keepalive = 0;
  DATA_PTR(self) = ctx;

  return self;
}

static mrb_value ngx_mrb_upstream_set_keepalive(mrb_state *mrb, mrb_value self)
{
  return mrb_nil_value();
}

static mrb_value ngx_mrb_upstream_set_cache(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  __ngx_http_upstream_keepalive_srv_conf_t *kcf = ngx_http_get_module_srv_conf(
      ngx_mrb_get_request(), __ngx_http_upstream_keepalive_module);
  unsigned int cache;

  mrb_get_args(mrb, "i", &cache);
  ctx->cache = cache;

  kcf->max_cached = cache;
  return mrb_fixnum_value(cache);
}

static mrb_value ngx_mrb_upstream_get_hostname(mrb_state *mrb, mrb_value self)
{
  ngx_mruby_upstream_context *ctx = DATA_PTR(self);
  return ctx->hostname;
}

void ngx_mrb_upstream_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_upstream;

  class_upstream = mrb_define_class_under(mrb, class, "Upstream", mrb->object_class);
  mrb_define_method(mrb, class_upstream, "initialize", ngx_mrb_upstream_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "keepalive=", ngx_mrb_upstream_set_keepalive, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "keepalive_cache=", ngx_mrb_upstream_set_cache, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_upstream, "hostname", ngx_mrb_upstream_get_hostname, MRB_ARGS_NONE());
}
