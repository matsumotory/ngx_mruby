/**
 * ngx_http_mruby_time.h - ngx_mruby mruby module header
 *
 * See Copyright Notice in ngx_http_mruby_module.c
 */

#ifndef NGX_HTTP_MRUBY_TIME_H
#define NGX_HTTP_MRUBY_TIME_H

#include <mruby.h>

void ngx_mrb_time_class_init(mrb_state *mrb, struct RClass *class);

#endif /* NGX_HTTP_MRUBY_TIME_H */
