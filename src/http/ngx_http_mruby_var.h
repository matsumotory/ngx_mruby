/*
// ngx_http_mruby_var.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#ifndef NGX_HTTP_MRUBY_VAR_H
#define NGX_HTTP_MRUBY_VAR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

/*
 * The variables that ngx_mruby's own methods read: Nginx::Request#get_body,
 * #hostname, #authority, #filename and #user, Nginx::Connection#remote_ip,
 * #remote_port, #local_ip and #local_port, and Nginx::Server#document_root,
 * #realpath_root and #path. They read them in C with
 * ngx_mrb_var_get_fixed(), without a Ruby call on an Nginx::Var, so a method
 * that a script defines on Nginx::Var does not change what they return.
 *
 * X(id, name): ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_<id>) reads $<name>.
 */
#define NGX_MRB_VAR_LIST(X)                                                                                            \
  X(REQUEST_BODY, "request_body")                                                                                      \
  X(HOST, "host")                                                                                                      \
  X(HTTP_HOST, "http_host")                                                                                            \
  X(REQUEST_FILENAME, "request_filename")                                                                              \
  X(REMOTE_USER, "remote_user")                                                                                        \
  X(REMOTE_ADDR, "remote_addr")                                                                                        \
  X(REMOTE_PORT, "remote_port")                                                                                        \
  X(SERVER_ADDR, "server_addr")                                                                                        \
  X(SERVER_PORT, "server_port")                                                                                        \
  X(DOCUMENT_ROOT, "document_root")                                                                                    \
  X(REALPATH_ROOT, "realpath_root")

#define NGX_MRB_VAR_ENUM(id, name) NGX_MRB_VAR_##id,
typedef enum { NGX_MRB_VAR_LIST(NGX_MRB_VAR_ENUM) NGX_MRB_VAR_COUNT } ngx_mrb_var_id_t;
#undef NGX_MRB_VAR_ENUM

/*
 * The value of the variable as a String, or nil when nginx has none. It
 * raises RuntimeError outside a request, as the methods of Nginx::Var do.
 */
mrb_value ngx_mrb_var_get_fixed(mrb_state *mrb, ngx_mrb_var_id_t id);

/*
 * The value of a variable as a String in *out: o itself when it is a String,
 * else what its to_s returns. The call runs under mrb_protect_error(), so
 * that it also works where no Ruby code runs (mrb->jmp is NULL, where a raise
 * would abort the process). A to_s that is missing, that raises or that does
 * not return a String gives FALSE, with the exception in *out.
 */
mrb_bool ngx_mrb_var_to_string(mrb_state *mrb, mrb_value o, mrb_value *out);

/*
 * Sets the variable to the value as a String. When the value cannot be
 * converted, it returns nil with the exception in mrb->exc, which the caller
 * clears.
 */
mrb_value ngx_mrb_var_set_vector(mrb_state *mrb, mrb_value self, char *k, int len, mrb_value o, ngx_http_request_t *r);

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_VAR_H
