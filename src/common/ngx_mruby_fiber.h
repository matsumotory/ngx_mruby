/*
// ngx_mruby_fiber.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_MRUBY_FIBER_H
#define NGX_MRUBY_FIBER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <mruby.h>

/*
// The record of the fiber that runs a handler, shared by the http and the
// stream modules (section 4 of docs/proposals/core-stabilization.md). Each
// module allocates it from the pool of the request or the session that owns
// it, as the first member of its own record, for each run of a handler.
//
// - fiber is the first member, so a mrb_value * to the fiber is also a
//   pointer to the record (ctx->fiber_proc of both modules).
// - slot is the slot of the fiber in the GC root holder of mrb
//   (ngx_http_mruby_gc_roots.h), or NGX_MRB_GC_ROOTS_NONE. The fiber takes
//   it at its first wait (ngx_mrb_fiber_hold); until then it is the running
//   fiber or in the GC arena of the call that created it. The slot is freed
//   when the fiber ends, normally or with an exception, or by the owner
//   hook.
// - timer is the one timer of the record, armed again for each sleep.
// - The owner hook (a request cleanup in http, a connection pool cleanup in
//   stream) is added once, at the first wait (hooked), before the wait is
//   armed. It calls ngx_mrb_fiber_cancel, which deletes the timer, frees the
//   slot and marks a waiting fiber CANCELLED.
*/
typedef enum {
  NGX_MRB_FIBER_RUNNING = 0,
  NGX_MRB_FIBER_WAITING,
  NGX_MRB_FIBER_READY,
  NGX_MRB_FIBER_DONE,
  NGX_MRB_FIBER_FAILED,
  NGX_MRB_FIBER_CANCELLED
} ngx_mrb_fiber_state_t;

/* What ngx_mrb_fiber_resume returns. */
typedef enum {
  /* the fiber yielded and waits */
  NGX_MRB_FIBER_WAITS = 0,
  /* the fiber returned; its value is in *value */
  NGX_MRB_FIBER_RETURNED,
  /* the fiber raised; the exception is logged, and mrb->exc is cleared */
  NGX_MRB_FIBER_RAISED
} ngx_mrb_fiber_outcome_t;

/* The counters of Nginx::Debug.stats that a record counts in. */
typedef enum { NGX_MRB_FIBER_HTTP = 0, NGX_MRB_FIBER_STREAM } ngx_mrb_fiber_protocol_t;

typedef struct {
  mrb_value fiber;
  mrb_state *mrb;
  mrb_int slot;
  ngx_mrb_fiber_state_t state;
  ngx_mrb_fiber_protocol_t protocol;
  ngx_event_t timer;
  unsigned hooked : 1;
} ngx_mrb_fiber_t;

/* Logs an exception of the fiber, for the request or the session in data. */
typedef void (*ngx_mrb_fiber_log_raise_pt)(mrb_state *mrb, mrb_value exc, void *data);

void ngx_mrb_fiber_prepare_proc(mrb_state *mrb, struct RProc *p);
void ngx_mrb_fiber_init(ngx_mrb_fiber_t *f, mrb_state *mrb, ngx_mrb_fiber_protocol_t protocol);
ngx_int_t ngx_mrb_fiber_hold(ngx_mrb_fiber_t *f);
void ngx_mrb_fiber_release(ngx_mrb_fiber_t *f);
void ngx_mrb_fiber_arm_timer(ngx_mrb_fiber_t *f, ngx_msec_t msec, ngx_event_handler_pt handler, void *data);
void ngx_mrb_fiber_timer_fired(ngx_mrb_fiber_t *f);
void ngx_mrb_fiber_delete_timer(ngx_mrb_fiber_t *f);
void ngx_mrb_fiber_cancel(ngx_mrb_fiber_t *f);
ngx_mrb_fiber_outcome_t ngx_mrb_fiber_resume(ngx_mrb_fiber_t *f, mrb_value *value, ngx_mrb_fiber_log_raise_pt log_raise,
                                             void *log_data);

#ifdef NGX_MRUBY_DEBUG_STATS
/*
// The counters of Nginx::Debug.stats (src/http/ngx_http_mruby_debug.c): the
// timers of Nginx::Async.sleep (http) or of Nginx::Stream::Async.sleep
// (stream) that have neither fired nor been deleted, and the fibers that
// hold a slot in the GC root holder. Signed, so that a counter counted down
// twice shows as negative.
*/
ngx_int_t ngx_mrb_fiber_debug_timers(ngx_mrb_fiber_protocol_t protocol);
ngx_int_t ngx_mrb_fiber_debug_held(ngx_mrb_fiber_protocol_t protocol);
#endif

#endif // NGX_MRUBY_FIBER_H
