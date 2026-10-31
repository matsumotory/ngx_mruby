/*
// ngx_http_mruby_debug.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_DEBUG_H
#define NGX_HTTP_MRUBY_DEBUG_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>

#ifdef NGX_MRUBY_DEBUG_STATS
void ngx_mrb_debug_class_init(mrb_state *mrb, struct RClass *class);

/*
// gc_root and gc_root_fibers of Nginx::Debug.stats count the objects that
// ngx_mruby itself keeps from the GC: those registered with
// mrb_gc_register() and not yet unregistered, and those in the GC root
// holders of ngx_http_mruby_gc_roots.h. The two macros send each call in a
// source file that includes this header to a function of
// ngx_http_mruby_debug.c, which calls the mruby function and then counts the
// call. A source file of the http or
// the stream module that calls mrb_gc_register() or mrb_gc_unregister()
// includes this header; test/soak/run.sh checks that it does. <mruby.h>,
// included above, declares the two functions before the macros are defined.
*/
void ngx_mrb_debug_gc_register(mrb_state *mrb, mrb_value obj);
void ngx_mrb_debug_gc_unregister(mrb_state *mrb, mrb_value obj);
#define mrb_gc_register(mrb, obj) ngx_mrb_debug_gc_register(mrb, obj)
#define mrb_gc_unregister(mrb, obj) ngx_mrb_debug_gc_unregister(mrb, obj)
/*
// Counts an object that ngx_mrb_gc_roots_add() stores in the holder of its
// mrb_state (n = 1) or that ngx_mrb_gc_roots_remove() releases (n = -1), in
// gc_root and gc_root_fibers (see ngx_http_mruby_gc_roots.h).
*/
void ngx_mrb_debug_gc_root_track(mrb_value obj, ngx_int_t n);
#endif

#endif // NGX_HTTP_MRUBY_DEBUG_H
