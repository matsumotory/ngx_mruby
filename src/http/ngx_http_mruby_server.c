/*
// ngx_http_mruby_server.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_server.h"

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include <mruby/hash.h>
#include <mruby/string.h>

static mrb_value ngx_mrb_get_server_var_docroot(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "document_root", 0, NULL);
}

static mrb_value ngx_mrb_get_server_var_realpath_root(mrb_state *mrb, mrb_value self)
{
  return mrb_funcall(mrb, ngx_mrb_get_request_var(mrb, self), "realpath_root", 0, NULL);
}

static mrb_value ngx_mrb_add_listener(mrb_state *mrb, mrb_value self)
{
  // ref: http/ngx_http_core_module.c ngx_http_core_listen
  ngx_http_mruby_srv_conf_t *mscf = mrb->ud;
  ngx_http_core_srv_conf_t *cscf = mscf->cscf;
  ngx_conf_t *cf = mscf->cf;
  ngx_str_t addr;
  ngx_url_t u;
  ngx_http_listen_opt_t lsopt;
  mrb_value listener, address;

  mrb_get_args(mrb, "H", &listener);
  address = mrb_hash_get(mrb, listener, mrb_check_intern_cstr(mrb, "address"));
  addr.data = (u_char *)RSTRING_PTR(address);
  addr.len = RSTRING_LEN(address);

  ngx_memzero(&u, sizeof(ngx_url_t));
  u.url = addr;
  u.listen = 1;
  u.default_port = 80;
  cscf->listen = 1;

  if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
    if (u.err) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in \"%V\" of the \"listen\" directive via mruby", u.err, &u.url);
    }

    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_add_listener ngx_parse_url failed");
  }

  ngx_memzero(&lsopt, sizeof(ngx_http_listen_opt_t));
#if (nginx_version < 1015010)
  ngx_memcpy(&lsopt.sockaddr.sockaddr, &u.sockaddr, u.socklen);
#else
  ngx_memcpy(lsopt.sockaddr, &u.sockaddr, u.socklen);
#endif
  lsopt.socklen = u.socklen;
  lsopt.backlog = NGX_LISTEN_BACKLOG;
  lsopt.rcvbuf = -1;
  lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
  lsopt.setfib = -1;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
  lsopt.fastopen = -1;
#endif
  lsopt.wildcard = u.wildcard;
#if (NGX_HAVE_INET6)
  lsopt.ipv6only = 1;
#endif
  if (mrb_bool(mrb_hash_get(mrb, listener, mrb_check_intern_cstr(mrb, "ssl")))) {
#if (NGX_HTTP_SSL)
    lsopt.ssl = 1;
#else
    mrb_raise(mrb, E_RUNTIME_ERROR, "the ssl symbol requires ngx_http_ssl_module");
#endif
  }

  if (mrb_bool(mrb_hash_get(mrb, listener, mrb_check_intern_cstr(mrb, "http2")))) {
#if (NGX_HTTP_V2)
    lsopt.http2 = 1;
#else
    mrb_raise(mrb, E_RUNTIME_ERROR, "the http2 symbol requires ngx_http_http2_module");
#endif
  }
#if (nginx_version < 1015010)
  (void)ngx_sock_ntop(&lsopt.sockaddr.sockaddr, lsopt.socklen, lsopt.addr, NGX_SOCKADDR_STRLEN, 1);
#else
  (void)ngx_sock_ntop(lsopt.sockaddr, lsopt.socklen, lsopt.sockaddr,addr_text, NGX_SOCKADDR_STRLEN, 1);
#endif
  if (ngx_http_add_listen(cf, cscf, &lsopt) == NGX_OK) {
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "add listener %V via mruby", &addr);
    return mrb_true_value();
  }

  mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_add_listener ngx_http_add_listen failed");
}

void ngx_mrb_server_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_server;

  class_server = mrb_define_class_under(mrb, class, "Server", mrb->object_class);
  mrb_define_method(mrb, class_server, "document_root", ngx_mrb_get_server_var_docroot, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_server, "path", ngx_mrb_get_server_var_realpath_root, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_server, "realpath_root", ngx_mrb_get_server_var_realpath_root, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_server, "add_listener", ngx_mrb_add_listener, MRB_ARGS_REQ(1));
}
