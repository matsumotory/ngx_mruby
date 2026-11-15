/*
// ngx_mruby_exec.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_MRUBY_EXEC_H
#define NGX_MRUBY_EXEC_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>

/*
 * The execution context: what the Ruby code that runs now runs for, in the
 * http and the stream module (section 2.1 of docs/proposals/core-alpha1.md).
 *
 * Each mrb_state has one ngx_mrb_exec_holder_t, reached through mrb->ud, that
 * points at the context of the code that runs now. Every place that runs Ruby
 * code pushes a context that lives on its C stack (ngx_mrb_exec_push), and
 * puts back the one that ran before when the code returns or its fiber yields
 * (ngx_mrb_exec_pop). The context belongs to the state, so the two states
 * that exist while nginx reads a new configuration each have their own.
 *
 * A Ruby method gets the context through ngx_mrb_exec_require(mrb, allowed,
 * name), with allowed the mask of the kinds where it works, and raises a
 * RuntimeError anywhere else.
 */

/*
 * What runs. The kinds from NGX_MRB_EXEC_HTTP_SET to
 * NGX_MRB_EXEC_HTTP_BODY_FILTER are the handlers of an HTTP request, in the
 * order of ngx_http_mruby_handler_kind_t (src/http/ngx_http_mruby_core.h),
 * which names them.
 */
typedef enum {
  NGX_MRB_EXEC_NONE = 0,
  NGX_MRB_EXEC_HTTP_SET,
  NGX_MRB_EXEC_HTTP_POST_READ,
  NGX_MRB_EXEC_HTTP_SERVER_REWRITE,
  NGX_MRB_EXEC_HTTP_REWRITE,
  NGX_MRB_EXEC_HTTP_ACCESS,
  NGX_MRB_EXEC_HTTP_CONTENT,
  NGX_MRB_EXEC_HTTP_LOG,
  NGX_MRB_EXEC_HTTP_HEADER_FILTER,
  NGX_MRB_EXEC_HTTP_BODY_FILTER,
  // mruby_init and mruby_stream_init
  NGX_MRB_EXEC_INIT,
  // mruby_init_worker, mruby_exit_worker and their stream forms
  NGX_MRB_EXEC_WORKER,
  // mruby_server_context_handler_code
  NGX_MRB_EXEC_HTTP_SERVER_CONTEXT,
  // mruby_ssl_handshake_handler and its inline form
  NGX_MRB_EXEC_SSL_HANDSHAKE,
  // mruby_stream_server_context_code
  NGX_MRB_EXEC_STREAM_SERVER_CONTEXT,
  // mruby_stream and mruby_stream_code
  NGX_MRB_EXEC_STREAM
} ngx_mrb_exec_kind_t;

typedef struct ngx_mrb_exec_s {
  ngx_mrb_exec_kind_t kind;
  // ngx_http_request_t * (the handlers of a request), ngx_stream_session_t *
  // (NGX_MRB_EXEC_STREAM), ngx_connection_t * (NGX_MRB_EXEC_SSL_HANDSHAKE),
  // ngx_conf_t * (the code that runs while nginx reads the configuration) or
  // NULL (the worker hooks)
  void *on;
  // the server configuration of the SSL handshake handler and of the server
  // context code, or NULL
  void *srv_conf;
  // the record of the fiber of an HTTP handler while that fiber runs
  // (ngx_http_mrb_fiber_t), or NULL
  void *record;
  // where Nginx.log writes; NULL for the cycle's log
  ngx_log_t *log;
  // the context that ran before this one
  struct ngx_mrb_exec_s *prev;
} ngx_mrb_exec_t;

typedef struct {
  ngx_mrb_exec_t *current;
} ngx_mrb_exec_holder_t;

#define NGX_MRB_EXEC_BIT(kind) ((ngx_uint_t)1 << (kind))

// every handler and filter of an HTTP request
#define NGX_MRB_EXEC_HTTP_REQUEST                                                                                      \
  (NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SET) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_POST_READ) |                           \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SERVER_REWRITE) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_REWRITE) |                  \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_ACCESS) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_CONTENT) |                          \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_LOG) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_HEADER_FILTER) |                       \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_BODY_FILTER))

// the phase handlers that run before the response, which nginx calls from
// the checkers of their phases
#define NGX_MRB_EXEC_HTTP_PHASES                                                                                       \
  (NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_POST_READ) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SERVER_REWRITE) |                \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_REWRITE) | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_ACCESS) |                          \
   NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_CONTENT))

// what changes the request: mruby_set and the phase handlers
#define NGX_MRB_EXEC_HTTP_CHANGE_REQUEST (NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SET) | NGX_MRB_EXEC_HTTP_PHASES)

// what changes the head of the response: every handler and filter of the
// request but a log handler, and only while nginx has not sent the response
// header, which the method checks itself (r->header_sent)
#define NGX_MRB_EXEC_HTTP_RESPONSE_HEAD (NGX_MRB_EXEC_HTTP_REQUEST & ~NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_LOG))

// Nginx.rputs and Nginx.echo: the phase handlers; a body filter keeps what it
// does today, which the table of section 2.1 does not change
#define NGX_MRB_EXEC_HTTP_OUTPUT (NGX_MRB_EXEC_HTTP_PHASES | NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_BODY_FILTER))

// where Nginx::Async may suspend the fiber of a handler
#define NGX_MRB_EXEC_HTTP_WAIT (NGX_MRB_EXEC_BIT(NGX_MRB_EXEC_HTTP_SET) | NGX_MRB_EXEC_HTTP_PHASES)

// everywhere, for the methods that need no request
#define NGX_MRB_EXEC_ANY (~(ngx_uint_t)0)

static ngx_inline ngx_mrb_exec_t *ngx_mrb_exec_current(mrb_state *mrb)
{
  ngx_mrb_exec_holder_t *holder = mrb->ud;

  return holder != NULL ? holder->current : NULL;
}

// exec lives on the C stack of the caller until ngx_mrb_exec_pop
static ngx_inline void ngx_mrb_exec_push(mrb_state *mrb, ngx_mrb_exec_t *exec)
{
  ngx_mrb_exec_holder_t *holder = mrb->ud;

  exec->prev = holder->current;
  holder->current = exec;
}

// puts back the context that ran before exec; a second call does nothing more
static ngx_inline void ngx_mrb_exec_pop(mrb_state *mrb, ngx_mrb_exec_t *exec)
{
  ngx_mrb_exec_holder_t *holder = mrb->ud;

  holder->current = exec->prev;
}

/*
 * Raises the RuntimeError of a method that is called outside the kinds of
 * allowed, with exec the context that runs (or NULL). name names the method;
 * when it ends with '.' or '#', the name that the method was called with is
 * appended, so that one C function defined under several names names the one
 * that was called. The messages that methods raised before 3.0.0 stay:
 *
 * - "this method can only be used while processing a request" for a method
 *   of a request outside one, and "... a stream session" for a method of a
 *   stream session outside one;
 * - "NAME can only be used in PLACE" for a method that works in one kind of
 *   handler (Nginx::SSL, add_listener, the body of Nginx::Filter);
 * - otherwise "NAME is not available in KIND", as Nginx::Async raises since
 *   2.7.1.
 */
mrb_noreturn void ngx_mrb_exec_raise(mrb_state *mrb, ngx_mrb_exec_t *exec, ngx_uint_t allowed, const char *name);

/*
 * The context of a push lives on the C stack of the function that pushed it,
 * so the region between ngx_mrb_exec_push and ngx_mrb_exec_pop is not left
 * without the pop: when an allocation fails, mruby raises NoMemoryError
 * from the C function that allocates, and inside another mruby call
 * (mrb->jmp is set) that longjmps to the outer call, which would go on with
 * the holder pointing at a frame that is gone. The rule:
 *
 * - A region that can run inside another mruby call goes through
 *   ngx_mrb_exec_run, which protects it there and puts the context back
 *   before the exception goes on to the outer call. ngx_mrb_run is such a
 *   region: nginx runs the handlers of a location inside the Ruby call of
 *   Nginx.redirect, and the output filters inside the call that sends a
 *   response. Every other push of the http module runs inside it
 *   (ngx_mrb_run_fiber of a handler) or from nginx's events
 *   (ngx_mrb_post_fiber, ngx_http_mrb_resume_set, the SSL handshake), and
 *   ngx_mrb_exec_pop puts back the context from before its own push, so the
 *   pop of ngx_mrb_run is right also when an inner region was left.
 * - A region that runs only from nginx's events, or while nginx reads the
 *   configuration or starts or ends a worker, where mrb->jmp is NULL, pushes
 *   and pops directly: a raise without a jmp aborts the process (exc_throw
 *   in mruby's error.c), and the calls that run Ruby code there protect it
 *   themselves (mrb_toplevel_run, ngx_mrb_fiber_resume).
 */
typedef ngx_int_t (*ngx_mrb_exec_body_pt)(mrb_state *mrb, void *data);

ngx_int_t ngx_mrb_exec_run(mrb_state *mrb, ngx_mrb_exec_t *exec, ngx_mrb_exec_body_pt body, void *data);

// Raises "NAME is not available after WHEN", with name as above.
mrb_noreturn void ngx_mrb_exec_raise_after(mrb_state *mrb, const char *name, const char *when);

// The name of a kind for messages ("a log handler").
const char *ngx_mrb_exec_kind_name(ngx_mrb_exec_kind_t kind);

static ngx_inline ngx_mrb_exec_t *ngx_mrb_exec_require(mrb_state *mrb, ngx_uint_t allowed, const char *name)
{
  ngx_mrb_exec_t *exec = ngx_mrb_exec_current(mrb);

  if (exec == NULL || !(allowed & NGX_MRB_EXEC_BIT(exec->kind))) {
    ngx_mrb_exec_raise(mrb, exec, allowed, name);
  }
  return exec;
}

#endif // NGX_MRUBY_EXEC_H
