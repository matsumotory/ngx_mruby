/*
// ngx_stream_mruby_connection.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_connection.h"

#include <ngx_stream.h>
#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

typedef struct {
  mrb_value upstream;
  ngx_stream_upstream_rr_peer_t *target;
  ngx_stream_upstream_rr_peers_t *peers;
  ngx_stream_upstream_srv_conf_t *us;
} ngx_stream_mruby_upstream_context;

static void ngx_stream_mrb_upstream_context_free(mrb_state *mrb, void *p)
{
  ngx_stream_mruby_upstream_context *ctx = p;
  mrb_free(mrb, ctx);
}

static const struct mrb_data_type ngx_stream_mrb_upstream_context_type = {
    "ngx_stream_mrb_upstream_context", ngx_stream_mrb_upstream_context_free,
};

static mrb_value ngx_stream_mrb_connection_init(mrb_state *mrb, mrb_value self)
{
  ngx_uint_t i;
  mrb_value upstream;
  ngx_stream_mruby_upstream_context *ctx;
  ngx_stream_upstream_main_conf_t *umcf;
  ngx_stream_upstream_srv_conf_t **usp;
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  mrb_get_args(mrb, "o", &upstream);

  ctx = (ngx_stream_mruby_upstream_context *)DATA_PTR(self);
  if (ctx) {
    mrb_free(mrb, ctx);
  }
  DATA_TYPE(self) = &ngx_stream_mrb_upstream_context_type;
  DATA_PTR(self) = NULL;
  ctx = (ngx_stream_mruby_upstream_context *)mrb_malloc(mrb, sizeof(ngx_stream_mruby_upstream_context));

  ctx->upstream = upstream;
  ctx->target = NULL;
  ctx->peers = NULL;
  ctx->us = NULL;

  umcf = ngx_stream_get_module_main_conf(s, ngx_stream_upstream_module);
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

static mrb_value ngx_stream_mrb_upstream_get_server(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_upstream_context *ctx = DATA_PTR(self);
  if (ctx->target == NULL) {
    return mrb_nil_value();
  }
  return mrb_str_new(mrb, (char *)ctx->target->name.data, ctx->target->name.len);
}

static mrb_value ngx_stream_mrb_upstream_set_server(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_upstream_context *ctx = DATA_PTR(self);
  ngx_url_t u;
  mrb_value server;
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  mrb_get_args(mrb, "o", &server);

  ngx_memzero(&u, sizeof(ngx_url_t));
  u.url.data = (u_char *)RSTRING_PTR(server);
  u.url.len = RSTRING_LEN(server);
  u.no_resolve = 1;

  if (ngx_parse_url(s->connection->pool, &u) != NGX_OK) {
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

static mrb_value ngx_stream_mrb_connection_get_status(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;

  return mrb_fixnum_value((mrb_int)ictx->stream_status);
}

static mrb_value ngx_stream_mrb_connection_status(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  mrb_int status;

  mrb_get_args(mrb, "i", &status);

  ictx->stream_status = (ngx_int_t)status;

  return self;
}

static mrb_value ngx_stream_mrb_remote_ip(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  return mrb_str_new(mrb, (const char *)s->connection->addr_text.data, s->connection->addr_text.len);
}

static mrb_value ngx_stream_mrb_proxy_protocol_addr(mrb_state *mrb, mrb_value self)
{
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  return mrb_str_new(mrb, (const char *)s->connection->proxy_protocol_addr.data,
                     s->connection->proxy_protocol_addr.len);
}

void ngx_stream_mrb_conn_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_conn;

  class_conn = mrb_define_class_under(mrb, class, "Connection", mrb->object_class);
  mrb_define_method(mrb, class_conn, "initialize", ngx_stream_mrb_connection_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_conn, "upstream_server", ngx_stream_mrb_upstream_get_server, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "upstream_server=", ngx_stream_mrb_upstream_set_server, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_conn, "stream_status", ngx_stream_mrb_connection_get_status, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "stream_status=", ngx_stream_mrb_connection_status, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_conn, "remote_ip", ngx_stream_mrb_remote_ip, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "remote_addr", ngx_stream_mrb_remote_ip, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "proxy_protocol_ip", ngx_stream_mrb_proxy_protocol_addr, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_conn, "proxy_protocol_addr", ngx_stream_mrb_proxy_protocol_addr, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "remote_ip", ngx_stream_mrb_remote_ip, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "remote_addr", ngx_stream_mrb_remote_ip, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "proxy_protocol_ip", ngx_stream_mrb_proxy_protocol_addr, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "proxy_protocol_addr", ngx_stream_mrb_proxy_protocol_addr, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "stream_status", ngx_stream_mrb_connection_get_status, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_conn, "stream_status=", ngx_stream_mrb_connection_status, MRB_ARGS_REQ(1));
}
