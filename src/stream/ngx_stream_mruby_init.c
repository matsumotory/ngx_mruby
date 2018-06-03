/*
// ngx_stream_mruby_init.c - ngx_mruby mruby init functions
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_stream_mruby_init.h"

#include "ngx_stream_mruby_core.h"
#include "ngx_stream_mruby_connection.h"

#include <mruby.h>

#define GC_ARENA_RESTORE mrb_gc_arena_restore(mrb, 0);

ngx_int_t ngx_stream_mrb_class_init(mrb_state *mrb)
{
  struct RClass *top;
  struct RClass *class;

  /* define Nginx::Stream class */
  top = mrb_define_class(mrb, "Nginx", mrb->object_class);
  class = mrb_define_class_under(mrb, top, "Stream", mrb->object_class);

  ngx_stream_mrb_core_class_init(mrb, class);
  GC_ARENA_RESTORE;
  ngx_stream_mrb_conn_class_init(mrb, class);
  GC_ARENA_RESTORE;

  return NGX_OK;
}
