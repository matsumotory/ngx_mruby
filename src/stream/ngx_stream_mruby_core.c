/*
// ngx_stream_mruby_core.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_core.h"

#include "ngx_stream_mruby_module.h" // FIXME: ngx_stream_mruby_internal_ctx_t and MODULE_NAME

#include <mruby/hash.h>
#include <mruby/string.h>

static mrb_value ngx_stream_mrb_errlogger(mrb_state *mrb, mrb_value self)
{
  mrb_value msg;
  mrb_int log_level;
  ngx_stream_mruby_internal_ctx_t *ictx = mrb->ud;
  ngx_stream_session_t *s = ictx->s;

  if (s == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't use logger at this phase. only use at session stream phase");
  }

  mrb_get_args(mrb, "io", &log_level, &msg);
  if (log_level < 0) {
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "%s ERROR %s: log level is not positive number", MODULE_NAME,
                  __func__);
    return self;
  }
  msg = mrb_obj_as_string(mrb, msg);
  ngx_log_error((ngx_uint_t)log_level, s->connection->log, 0, "%*s", RSTRING_LEN(msg), RSTRING_PTR(msg));

  return self;
}

static mrb_value ngx_stream_mrb_get_ngx_mruby_name(mrb_state *mrb, mrb_value self)
{
  return mrb_str_new_lit(mrb, MODULE_NAME);
}

static mrb_value ngx_stream_mrb_add_listener(mrb_state *mrb, mrb_value self)
{
  ngx_stream_core_main_conf_t *cmcf;
  ngx_stream_mruby_srv_conf_t *mscf = mrb->ud;
  ngx_stream_core_srv_conf_t *cscf = mscf->ctx->cscf;
  ngx_conf_t *cf = mscf->ctx->cf;
  mrb_value listener, address;
  ngx_str_t addr;
  ngx_url_t u;
  ngx_uint_t i;
  ngx_stream_listen_t *ls, *als;

  mrb_get_args(mrb, "H", &listener);
  address = mrb_hash_get(mrb, listener, mrb_check_intern_cstr(mrb, "address"));
  addr.data = (u_char *)RSTRING_PTR(address);
  addr.len = RSTRING_LEN(address);

  ngx_memzero(&u, sizeof(ngx_url_t));

  u.url = addr;
  u.listen = 1;
  cscf->listen = 1;

  if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
    if (u.err) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in \"%V\" of the \"listen\" directive via mruby", u.err, &u.url);
    }

    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_stream_mrb_add_listener ngx_parse_url failed");
  }

  cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

  ls = ngx_array_push(&cmcf->listen);
  if (ls == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_stream_mrb_add_listener ngx_array_push failed");
  }

  ngx_memzero(ls, sizeof(ngx_stream_listen_t));
  ngx_memcpy(&ls->sockaddr.sockaddr, &u.sockaddr, u.socklen);

  ls->socklen = u.socklen;
  ls->backlog = NGX_LISTEN_BACKLOG;
#if (nginx_version >= 1013000)
  ls->rcvbuf = -1;
  ls->sndbuf = -1;
#endif
  ls->type = SOCK_STREAM;
  ls->wildcard = u.wildcard;
  ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6)
  ls->ipv6only = 1;
#endif

#if !(NGX_WIN32)
  if (mrb_bool(mrb_hash_get(mrb, listener, mrb_check_intern_cstr(mrb, "udp")))) {
    ls->type = SOCK_DGRAM;
  }
#endif

  if (ls->type == SOCK_DGRAM) {
#if (NGX_STREAM_SSL)
    if (ls->ssl) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "\"ssl\" parameter is incompatible with \"udp\"");
    }
#endif

    if (ls->so_keepalive) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "\"so_keepalive\" parameter is incompatible with \"udp\"");
    }

    if (ls->proxy_protocol) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "\"proxy_protocol\" parameter is incompatible with \"udp\"");
    }
  }

  als = cmcf->listen.elts;

  for (i = 0; i < cmcf->listen.nelts - 1; i++) {
    if (ls->type != als[i].type) {
      continue;
    }

    if (ngx_cmp_sockaddr(&als[i].sockaddr.sockaddr, als[i].socklen, &ls->sockaddr.sockaddr, ls->socklen, 1) != NGX_OK) {
      continue;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate \"%V\" address and port pair", &u.url);
    mrb_raise(mrb, E_RUNTIME_ERROR, "duplicate address and port pair");
  }

  return mrb_true_value();
}

void ngx_stream_mrb_core_class_init(mrb_state *mrb, struct RClass *class)
{
  mrb_define_const(mrb, class, "OK", mrb_fixnum_value(NGX_OK));
  mrb_define_const(mrb, class, "ERROR", mrb_fixnum_value(NGX_ERROR));
  mrb_define_const(mrb, class, "AGAIN", mrb_fixnum_value(NGX_AGAIN));
  mrb_define_const(mrb, class, "BUSY", mrb_fixnum_value(NGX_BUSY));
  mrb_define_const(mrb, class, "DONE", mrb_fixnum_value(NGX_DONE));
  mrb_define_const(mrb, class, "DECLINED", mrb_fixnum_value(NGX_DECLINED));
  mrb_define_const(mrb, class, "ABORT", mrb_fixnum_value(NGX_ABORT));
  // error log priority
  mrb_define_const(mrb, class, "LOG_STDERR", mrb_fixnum_value(NGX_LOG_STDERR));
  mrb_define_const(mrb, class, "LOG_EMERG", mrb_fixnum_value(NGX_LOG_EMERG));
  mrb_define_const(mrb, class, "LOG_ALERT", mrb_fixnum_value(NGX_LOG_ALERT));
  mrb_define_const(mrb, class, "LOG_CRIT", mrb_fixnum_value(NGX_LOG_CRIT));
  mrb_define_const(mrb, class, "LOG_ERR", mrb_fixnum_value(NGX_LOG_ERR));
  mrb_define_const(mrb, class, "LOG_WARN", mrb_fixnum_value(NGX_LOG_WARN));
  mrb_define_const(mrb, class, "LOG_NOTICE", mrb_fixnum_value(NGX_LOG_NOTICE));
  mrb_define_const(mrb, class, "LOG_INFO", mrb_fixnum_value(NGX_LOG_INFO));
  mrb_define_const(mrb, class, "LOG_DEBUG", mrb_fixnum_value(NGX_LOG_DEBUG));

  mrb_define_class_method(mrb, class, "errlogger", ngx_stream_mrb_errlogger, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class, "log", ngx_stream_mrb_errlogger, MRB_ARGS_REQ(2));
  mrb_define_class_method(mrb, class, "module_name", ngx_stream_mrb_get_ngx_mruby_name, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class, "add_listener", ngx_stream_mrb_add_listener, MRB_ARGS_REQ(1));
}
