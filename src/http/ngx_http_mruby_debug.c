/*
// ngx_http_mruby_debug.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/*
// Nginx::Debug exposes the counters that the memory soak test (test/soak/)
// compares between samples. It exists only in builds compiled with
// -DNGX_MRUBY_DEBUG_STATS. The default builds of build.sh and test.sh do not
// define it, and this file then compiles to nothing. The file is always
// listed in config: guarding it here keeps config free of a check on the
// compiler flags.
*/

#include "ngx_http_mruby_debug.h"

#ifdef NGX_MRUBY_DEBUG_STATS

#include "ngx_http_mruby_async.h"

#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/variable.h>

/*
// The global variable that mrb_gc_register() appends to in mruby 3.x and 4.0
// (GC_ROOT_SYM in mruby/src/gc.c). mruby 4.1 keeps the root set in
// mrb->gc.root instead and does not define this variable.
*/
#define NGX_MRB_DEBUG_GC_ROOT_NAME "_gc_root_"

/*
// The objects that ngx_mruby has registered with mrb_gc_register() and not
// yet unregistered, and the fibers among them. They count the calls that go
// through the macros of ngx_http_mruby_debug.h, in every mrb_state of the
// process: the one of the http module and the one of the stream module.
// Signed, so that more unregistrations than registrations show as negative.
*/
static ngx_int_t ngx_mrb_debug_gc_root_count = 0;
static ngx_int_t ngx_mrb_debug_gc_root_fibers_count = 0;

static void ngx_mrb_debug_gc_root_add(mrb_value obj, ngx_int_t n)
{
  /* mrb_gc_register() and mrb_gc_unregister() ignore immediate values */
  if (mrb_immediate_p(obj)) {
    return;
  }
  ngx_mrb_debug_gc_root_count += n;
  if (mrb_type(obj) == MRB_TT_FIBER) {
    ngx_mrb_debug_gc_root_fibers_count += n;
  }
}

/* The parentheses around the name call the mruby function, not the macro. */
void ngx_mrb_debug_gc_register(mrb_state *mrb, mrb_value obj)
{
  (mrb_gc_register)(mrb, obj);
  ngx_mrb_debug_gc_root_add(obj, 1);
}

void ngx_mrb_debug_gc_unregister(mrb_state *mrb, mrb_value obj)
{
  (mrb_gc_unregister)(mrb, obj);
  ngx_mrb_debug_gc_root_add(obj, -1);
}

static void ngx_mrb_debug_stats_set(mrb_state *mrb, mrb_value stats, const char *key, mrb_int value)
{
  mrb_hash_set(mrb, stats, mrb_symbol_value(mrb_intern_cstr(mrb, key)), mrb_int_value(mrb, value));
}

static mrb_value ngx_mrb_debug_stats(mrb_state *mrb, mrb_value self)
{
  mrb_value stats, root;
  mrb_int root_len = 0, root_fibers = 0, i;
  /* Read these before this method allocates any object. */
  mrb_int live = (mrb_int)mrb->gc.live;
  mrb_int arena_idx = (mrb_int)mrb->gc.arena_idx;

  root = mrb_gv_get(mrb, mrb_intern_lit(mrb, NGX_MRB_DEBUG_GC_ROOT_NAME));
  if (mrb_array_p(root)) {
    root_len = RARRAY_LEN(root);
    for (i = 0; i < root_len; i++) {
      if (mrb_type(RARRAY_PTR(root)[i]) == MRB_TT_FIBER) {
        root_fibers++;
      }
    }
  }

  stats = mrb_hash_new_capa(mrb, 7);
  ngx_mrb_debug_stats_set(mrb, stats, "gc_live", live);
  ngx_mrb_debug_stats_set(mrb, stats, "gc_root", (mrb_int)ngx_mrb_debug_gc_root_count);
  ngx_mrb_debug_stats_set(mrb, stats, "gc_root_fibers", (mrb_int)ngx_mrb_debug_gc_root_fibers_count);
  ngx_mrb_debug_stats_set(mrb, stats, "gc_arena_idx", arena_idx);
  ngx_mrb_debug_stats_set(mrb, stats, "timers", (mrb_int)ngx_mrb_async_debug_timers());
  /* mruby's own root set of this mrb_state, for as long as mruby keeps the array */
  if (mrb_array_p(root)) {
    ngx_mrb_debug_stats_set(mrb, stats, "gc_root_mruby", root_len);
    ngx_mrb_debug_stats_set(mrb, stats, "gc_root_fibers_mruby", root_fibers);
  }

  return stats;
}

static mrb_value ngx_mrb_debug_gc(mrb_state *mrb, mrb_value self)
{
  mrb_full_gc(mrb);
  return mrb_nil_value();
}

void ngx_mrb_debug_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_debug;

  class_debug = mrb_define_class_under(mrb, class, "Debug", mrb->object_class);
  mrb_define_class_method(mrb, class_debug, "stats", ngx_mrb_debug_stats, MRB_ARGS_NONE());
  mrb_define_class_method(mrb, class_debug, "gc", ngx_mrb_debug_gc, MRB_ARGS_NONE());
}

#endif /* NGX_MRUBY_DEBUG_STATS */
