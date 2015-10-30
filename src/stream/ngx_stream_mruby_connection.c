/*
// ngx_stream_mruby_connection.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_stream_mruby_module.c
*/

#include "ngx_stream_mruby_connection.h"

#include <ngx_stream.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/class.h>

static mrb_value ngx_stream_mrb_remote_ip(mrb_state *mrb, mrb_value self)
{
  ngx_stream_session_t *s = mrb->ud;

  return mrb_str_new(mrb, (const char *)s->connection->addr_text.data, s->connection->addr_text.len);
}

void ngx_stream_mrb_conn_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_conn;

  class_conn = mrb_define_class_under(mrb, class, "Connection", mrb->object_class);
  mrb_define_method(mrb, class_conn, "remote_ip", ngx_stream_mrb_remote_ip, MRB_ARGS_NONE());
}
