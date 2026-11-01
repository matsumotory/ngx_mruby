/*
// ngx_mruby_fiber.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/*
// The part of the record of a handler's fiber that does not depend on the
// protocol (see ngx_mruby_fiber.h): the slot in the GC root holder, the one
// timer, the owner hook's cancel, and the resume. The http and the stream
// modules call these functions from their own code for the request or the
// session: the owner hook, what a wait returns to nginx, and how the result
// of the code ends the handler.
*/

#include "ngx_mruby_fiber.h"

#include "../http/ngx_http_mruby_gc_roots.h"

#include <mruby/error.h>
#include <mruby/proc.h>

#ifdef NGX_MRUBY_DEBUG_STATS
static ngx_int_t ngx_mrb_fiber_debug_timers_count[2];
static ngx_int_t ngx_mrb_fiber_debug_held_count[2];

ngx_int_t ngx_mrb_fiber_debug_timers(ngx_mrb_fiber_protocol_t protocol)
{
  return ngx_mrb_fiber_debug_timers_count[protocol];
}

ngx_int_t ngx_mrb_fiber_debug_held(ngx_mrb_fiber_protocol_t protocol)
{
  return ngx_mrb_fiber_debug_held_count[protocol];
}

#define ngx_mrb_fiber_debug_count(counter, f, n) (counter)[(f)->protocol] += (n)
#else
#define ngx_mrb_fiber_debug_count(counter, f, n)
#endif

/*
// Prepares the RProc of a handler's code once, when the code is compiled or
// loaded, for every fiber that runs it: the code runs at the top level, with
// no enclosing proc and with Object as the target class of its definitions.
*/
void ngx_mrb_fiber_prepare_proc(mrb_state *mrb, struct RProc *p)
{
  p->upper = NULL;
  MRB_PROC_SET_TARGET_CLASS(p, mrb->object_class);
}

void ngx_mrb_fiber_init(ngx_mrb_fiber_t *f, mrb_state *mrb, ngx_mrb_fiber_protocol_t protocol)
{
  ngx_memzero(f, sizeof(ngx_mrb_fiber_t));
  f->fiber = mrb_nil_value();
  f->mrb = mrb;
  f->slot = NGX_MRB_GC_ROOTS_NONE;
  f->state = NGX_MRB_FIBER_RUNNING;
  f->protocol = protocol;
}

/*
// Keeps the fiber from the GC while nginx can resume it: called at each wait,
// before the wait is armed, and takes the slot at the first one. Returns
// NGX_ERROR when the fiber could not be stored; nothing is armed then.
// ngx_mrb_gc_roots_add() raises a NoMemoryError when the holder cannot grow.
*/
ngx_int_t ngx_mrb_fiber_hold(ngx_mrb_fiber_t *f)
{
  if (f->slot != NGX_MRB_GC_ROOTS_NONE) {
    return NGX_OK;
  }

  f->slot = ngx_mrb_gc_roots_add(f->mrb, f->fiber);
  if (f->slot == NGX_MRB_GC_ROOTS_NONE) {
    return NGX_ERROR;
  }
  ngx_mrb_fiber_debug_count(ngx_mrb_fiber_debug_held_count, f, 1);

  return NGX_OK;
}

/* Frees the slot of the fiber, once; a fiber without a slot is left as it is. */
void ngx_mrb_fiber_release(ngx_mrb_fiber_t *f)
{
  if (f->slot == NGX_MRB_GC_ROOTS_NONE) {
    return;
  }

  ngx_mrb_gc_roots_remove(f->mrb, f->slot);
  f->slot = NGX_MRB_GC_ROOTS_NONE;
  ngx_mrb_fiber_debug_count(ngx_mrb_fiber_debug_held_count, f, -1);
}

/*
// Arms the timer of the record for one sleep. The owner hook must be in place
// before the first call, so that the timer never fires on a freed pool.
*/
void ngx_mrb_fiber_arm_timer(ngx_mrb_fiber_t *f, ngx_msec_t msec, ngx_event_handler_pt handler, void *data)
{
  f->timer.handler = handler;
  f->timer.data = data;
  f->timer.log = ngx_cycle->log;

  if (!f->timer.timer_set) {
    ngx_mrb_fiber_debug_count(ngx_mrb_fiber_debug_timers_count, f, 1);
  }
  ngx_add_timer(&f->timer, msec);
}

/* Called by the handler of the timer: nginx has removed the timer already. */
void ngx_mrb_fiber_timer_fired(ngx_mrb_fiber_t *f)
{
  ngx_mrb_fiber_debug_count(ngx_mrb_fiber_debug_timers_count, f, -1);
}

void ngx_mrb_fiber_delete_timer(ngx_mrb_fiber_t *f)
{
  if (f->timer.timer_set) {
    ngx_del_timer(&f->timer);
    ngx_mrb_fiber_debug_count(ngx_mrb_fiber_debug_timers_count, f, -1);
  }
}

/*
// The body of the owner hook: the owner ends, so nginx will not resume the
// fiber. It deletes the timer, frees the slot, and marks a fiber that waits
// CANCELLED. For a fiber that has ended, nothing is left to do.
*/
void ngx_mrb_fiber_cancel(ngx_mrb_fiber_t *f)
{
  ngx_mrb_fiber_delete_timer(f);
  ngx_mrb_fiber_release(f);
  // nginx has taken the hook off its list to run it, so a later wait of the
  // same record adds a new one
  f->hooked = 0;
  if (f->state == NGX_MRB_FIBER_WAITING || f->state == NGX_MRB_FIBER_READY) {
    f->state = NGX_MRB_FIBER_CANCELLED;
  }
}

static mrb_value ngx_mrb_fiber_resume_body(mrb_state *mrb, void *data)
{
  return mrb_fiber_resume(mrb, *(mrb_value *)data, 0, NULL);
}

/*
// Starts or resumes the fiber, and returns whether it waits, returned or
// raised. The caller sets the current request or session for the time it
// runs.
//
// mruby passes an exception that ends a fiber resumed from C by longjmp to
// the innermost mrb_vm_exec or mrb_protect_error, if one runs (mrb->jmp is
// set); otherwise it returns with mrb->exc set. When this fiber runs inside
// another one, for example in the location that Nginx.redirect runs from
// Ruby code, that longjmp would leave through the nginx functions between
// the two (ngx_http_internal_redirect, the phase checkers), and nginx would
// not finish the request. mrb_protect_error stops the exception here. A
// fiber that nginx resumes directly needs no protection, and skips its cost.
//
// On every path that raised, the exception is logged once with log_raise and
// mrb->exc is cleared before this function returns: all requests or
// sessions share the mrb_state, and a later mrb_fiber_new would fail with an
// exception left in it. The slot is freed when the fiber ends.
*/
ngx_mrb_fiber_outcome_t ngx_mrb_fiber_resume(ngx_mrb_fiber_t *f, mrb_value *value, ngx_mrb_fiber_log_raise_pt log_raise,
                                             void *log_data)
{
  mrb_state *mrb = f->mrb;
  mrb_value v;
  mrb_bool raised = FALSE;

  f->state = NGX_MRB_FIBER_RUNNING;
  if (mrb->jmp == NULL) {
    v = mrb_fiber_resume(mrb, f->fiber, 0, NULL);
  } else {
    v = mrb_protect_error(mrb, ngx_mrb_fiber_resume_body, &f->fiber, &raised);
    if (raised) {
      mrb->exc = mrb_obj_ptr(v);
    }
  }

  if (mrb->exc) {
    f->state = NGX_MRB_FIBER_FAILED;
    ngx_mrb_fiber_release(f);
    if (log_raise != NULL) {
      log_raise(mrb, mrb_obj_value(mrb->exc), log_data);
    }
    mrb->exc = NULL;
    return NGX_MRB_FIBER_RAISED;
  }

  if (mrb_test(mrb_fiber_alive_p(mrb, f->fiber))) {
    f->state = NGX_MRB_FIBER_WAITING;
    return NGX_MRB_FIBER_WAITS;
  }

  f->state = NGX_MRB_FIBER_DONE;
  ngx_mrb_fiber_release(f);
  if (value != NULL) {
    *value = v;
  }

  return NGX_MRB_FIBER_RETURNED;
}
