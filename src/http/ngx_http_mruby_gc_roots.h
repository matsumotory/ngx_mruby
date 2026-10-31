/*
// ngx_http_mruby_gc_roots.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_GC_ROOTS_H
#define NGX_HTTP_MRUBY_GC_ROOTS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>

/*
// The objects that ngx_mruby keeps from the GC while C code holds them, for
// example the fiber of a handler while nginx can resume it. Each mrb_state
// of the http module and of the stream module has one holder: an Array that
// is registered with mrb_gc_register() once, when the state is opened, and
// stays registered until mrb_close(). An object is kept by storing it in a
// slot of the Array, and released by freeing the slot, so a request does
// not call mrb_gc_register() or mrb_gc_unregister() at all. A free slot
// holds the Integer index of the next free slot (-1 for none), and freed
// slots are taken again before the Array grows, so the Array is as long as
// the largest number of objects held at the same time.
//
// ngx_mrb_gc_roots_init() returns NGX_ERROR when the holder cannot be made.
// ngx_mrb_gc_roots_add() returns the slot, or -1 when the object could not
// be stored (an immediate value needs no slot and also gets -1);
// ngx_mrb_gc_roots_remove() frees a slot that ngx_mrb_gc_roots_add()
// returned, and ignores -1.
*/
#define NGX_MRB_GC_ROOTS_NONE ((mrb_int)-1)

ngx_int_t ngx_mrb_gc_roots_init(mrb_state *mrb);
mrb_int ngx_mrb_gc_roots_add(mrb_state *mrb, mrb_value obj);
void ngx_mrb_gc_roots_remove(mrb_state *mrb, mrb_int slot);

#endif // NGX_HTTP_MRUBY_GC_ROOTS_H
