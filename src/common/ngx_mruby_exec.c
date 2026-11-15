/*
// ngx_mruby_exec.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_mruby_exec.h"

#include <mruby/error.h>

const char *ngx_mrb_exec_kind_name(ngx_mrb_exec_kind_t kind)
{
  switch (kind) {
  case NGX_MRB_EXEC_HTTP_SET:
    return "an mruby_set handler";
  case NGX_MRB_EXEC_HTTP_POST_READ:
    return "a post_read handler";
  case NGX_MRB_EXEC_HTTP_SERVER_REWRITE:
    return "a server_rewrite handler";
  case NGX_MRB_EXEC_HTTP_REWRITE:
    return "a rewrite handler";
  case NGX_MRB_EXEC_HTTP_ACCESS:
    return "an access handler";
  case NGX_MRB_EXEC_HTTP_CONTENT:
    return "a content handler";
  case NGX_MRB_EXEC_HTTP_LOG:
    return "a log handler";
  case NGX_MRB_EXEC_HTTP_HEADER_FILTER:
    return "a header filter";
  case NGX_MRB_EXEC_HTTP_BODY_FILTER:
    return "a body filter";
  case NGX_MRB_EXEC_INIT:
    return "the init code";
  case NGX_MRB_EXEC_WORKER:
    return "a worker hook";
  case NGX_MRB_EXEC_HTTP_SERVER_CONTEXT:
  case NGX_MRB_EXEC_STREAM_SERVER_CONTEXT:
    return "the server context code";
  case NGX_MRB_EXEC_SSL_HANDSHAKE:
    return "the SSL handshake handler";
  case NGX_MRB_EXEC_STREAM:
    return "a stream handler";
  default:
    return "a context without a request handler";
  }
}

typedef struct {
  ngx_mrb_exec_body_pt body;
  void *data;
  ngx_int_t rc;
} ngx_mrb_exec_call_t;

static mrb_value ngx_mrb_exec_call(mrb_state *mrb, void *data)
{
  ngx_mrb_exec_call_t *call = data;

  call->rc = call->body(mrb, call->data);
  return mrb_nil_value();
}

ngx_int_t ngx_mrb_exec_run(mrb_state *mrb, ngx_mrb_exec_t *exec, ngx_mrb_exec_body_pt body, void *data)
{
  ngx_mrb_exec_call_t call;
  mrb_value exc;
  mrb_bool raised = FALSE;
  ngx_int_t rc;

  ngx_mrb_exec_push(mrb, exec);

  // Outside any mruby call a raise that body does not protect aborts the
  // process, so nothing runs on with the context, and the protection is not
  // paid for
  if (mrb->jmp == NULL) {
    rc = body(mrb, data);
    ngx_mrb_exec_pop(mrb, exec);
    return rc;
  }

  call.body = body;
  call.data = data;
  call.rc = NGX_ERROR;
  exc = mrb_protect_error(mrb, ngx_mrb_exec_call, &call, &raised);
  ngx_mrb_exec_pop(mrb, exec);
  if (raised) {
    // the exception goes on to the outer call, as it did without the
    // protection, now with the context of the outer call back in place
    mrb_exc_raise(mrb, exc);
  }

  return call.rc;
}

// Where a method that works in one kind of handler can be used, for the
// messages of 2.x, or NULL
static const char *ngx_mrb_exec_place_name(ngx_uint_t allowed)
{
  if (allowed == NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_SSL_HANDSHAKE)) {
    return "mruby_ssl_handshake_handler";
  }
  if (allowed == NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SERVER_CONTEXT)) {
    return "mruby_server_context_handler_code";
  }
  if (allowed == NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_STREAM_SERVER_CONTEXT)) {
    return "mruby_stream_server_context_code";
  }
  if (allowed == NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_BODY_FILTER)) {
    return "an output body filter";
  }
  return NULL;
}

// Whether the name of the method that was called goes after name
static ngx_flag_t ngx_mrb_exec_name_takes_mid(const char *name)
{
  size_t len = ngx_strlen(name);

  return len > 0 && (name[len - 1] == '.' || name[len - 1] == '#');
}

void ngx_mrb_exec_raise_after(mrb_state *mrb, const char *name, const char *when)
{
  if (ngx_mrb_exec_name_takes_mid(name)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s%n is not available after %s", name, mrb_get_mid(mrb), when);
  }
  mrb_raisef(mrb, E_RUNTIME_ERROR, "%s is not available after %s", name, when);
}

void ngx_mrb_exec_raise(mrb_state *mrb, ngx_mrb_exec_t *exec, ngx_uint_t allowed, const char *name)
{
  ngx_mrb_exec_kind_t kind = exec != NULL ? exec->kind : NGX_MRB_EXEC_NONE;
  const char *place;

  if ((allowed & ~NGX_MRB_EXEC_HTTP_REQUEST) == 0 && !(NGX_MRB_EXEC_HTTP_REQUEST & NGX_MRB_EXEC_BIT(kind))) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "this method can only be used while processing a request");
  }
  if (allowed == NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_STREAM) && kind != NGX_MRB_EXEC_STREAM) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "this method can only be used while processing a stream session");
  }

  place = ngx_mrb_exec_place_name(allowed);
  if (ngx_mrb_exec_name_takes_mid(name)) {
    if (place != NULL) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "%s%n can only be used in %s", name, mrb_get_mid(mrb), place);
    }
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s%n is not available in %s", name, mrb_get_mid(mrb),
               ngx_mrb_exec_kind_name(kind));
  }
  if (place != NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "%s can only be used in %s", name, place);
  }
  mrb_raisef(mrb, E_RUNTIME_ERROR, "%s is not available in %s", name, ngx_mrb_exec_kind_name(kind));
}
