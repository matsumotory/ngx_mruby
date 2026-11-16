/*
// ngx_mruby_code.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_MRUBY_CODE_H
#define NGX_MRUBY_CODE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>
#include <mruby/compile.h>

/*
// The code of a directive, shared by the http and the stream modules
// (section 2.6 of docs/proposals/core-alpha1.md): a file or an inline string,
// and the proc that it was compiled into.
//
// - cache is read by the http module only: the file of a code without it is
//   read and compiled again on each run, unless the location has
//   mruby_cache on (ngx_mrb_code_reload). The stream module compiles each
//   code once.
// - proc is the compiled code. ctx is the compiler context of the last
//   compile, until NGX_MRUBY_CODE_MRBC_CONTEXT_FREE frees it.
// - slot is the slot of proc in the GC root holder of the mrb_state that
//   compiled it (ngx_http_mruby_gc_roots.h), or NGX_MRB_GC_ROOTS_NONE.
//   ngx_mrb_code_compile takes the slot, and the proc stays in it until
//   mrb_close frees the holder. ngx_mrb_code_reload puts the new proc in the
//   same slot. The code of a request (mruby_add_handler) is never compiled
//   and has no slot.
//
// code_type_t is also the form of a directive: the file form takes the path
// of a script, the inline form (the directive whose name ends in _code) the
// code itself. It indexes the arrays of codes by form, which have
// NGX_MRB_CODE_FORMS elements.
*/
typedef enum code_type_t { NGX_MRB_CODE_TYPE_FILE, NGX_MRB_CODE_TYPE_STRING } code_type_t;

#define NGX_MRB_CODE_FORMS 2

typedef struct ngx_mrb_code_t {
  union code {
    char *file;
    char *string;
  } code;
  code_type_t code_type;
  unsigned int cache;
  struct RProc *proc;
  mrbc_context *ctx;
  mrb_int slot;
} ngx_mrb_code_t;

#define NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code)                                                                    \
  if (code != NGX_CONF_UNSET_PTR && mrb && (code)->ctx) {                                                              \
    mrbc_context_free(mrb, (code)->ctx);                                                                               \
    (code)->ctx = NULL;                                                                                                \
  }

/*
// Make a code from the path of a file or from an inline string, allocated
// from pool. A file is compiled without cache and a string with it, until
// the directive sets cache. Both return NGX_CONF_UNSET_PTR when an
// allocation fails.
*/
ngx_mrb_code_t *ngx_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *path);
ngx_mrb_code_t *ngx_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *string);

/*
// Compiles code into mrb while nginx reads the configuration: reads the
// file or the string with a new compiler context (the previous one is
// freed), prepares the proc for the fibers (ngx_mrb_fiber_prepare_proc) and
// stores it in the slot of the code. The proc is kept by the slot alone: the
// GC arena gets back the depth it had before the call. Logs a line at the
// info level through cf (which adds the file and the line of the
// configuration), with module_name, the MODULE_NAME of the caller, and
// func, the name of the directive function that compiles the code
// (test/t/cases/config_time_log.rb tells the lines of the stream module
// from those of the http module by it). code->cache in the line means
// something to the http module only. Returns NGX_ERROR when the file cannot be opened, the code does not
// compile, or the proc cannot be stored; the caller logs the error.
*/
ngx_int_t ngx_mrb_code_compile(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code, const char *module_name,
                               const char *func);

/*
// Reads the file of code again and compiles it, for a run of a code without
// cache (the http module). The new proc replaces the previous one in the slot
// of the code; a fiber that still runs the previous proc keeps it alive. A
// code without a slot (that of mruby_add_handler, made for one request)
// leaves its proc in the GC arena of the caller, which keeps it while the
// code runs. The file is read with fopen, which blocks the worker (see
// "Design principles" in AGENTS.md). Returns NGX_ERROR when the file cannot
// be opened or the code does not compile, and the code keeps its previous
// proc; and when the new proc cannot be stored, which only a missing holder
// causes (a bug, logged at the alert level by ngx_mrb_gc_roots_add).
*/
ngx_int_t ngx_mrb_code_reload(mrb_state *mrb, ngx_mrb_code_t *code);

/*
// Sets *field to the code of the directive that nginx reads now, for the
// http and the stream modules (section 2.5 of docs/proposals/core-alpha1.md).
// The first argument of the directive is the path of a script (form
// NGX_MRB_CODE_TYPE_FILE) or the code (NGX_MRB_CODE_TYPE_STRING); a file
// directive that takes two arguments accepts only "cache" as the second.
//
// A field that is set already (not NGX_CONF_UNSET_PTR) is refused with "is
// duplicated", which nginx prints as '"NAME" directive is duplicated': each
// field holds the code of one hook in one context, and the file and the
// inline form of a hook that share a field count as the same hook. The code
// is made from cf->pool and compiled into mrb (ngx_mrb_code_compile, which
// logs the compile line with module_name and func). It is in *field also when
// the compile fails, so that the cleanup of the configuration frees its
// compiler context. Returns NGX_CONF_OK, "is duplicated" or NGX_CONF_ERROR,
// after an error line that names module_name and func.
*/
char *ngx_mrb_code_set(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t **field, code_type_t form,
                       const char *module_name, const char *func);

/*
// The forms, for the post of a command entry that ngx_mrb_code_set serves:
// &ngx_mrb_code_forms[form] tells the directive function the form of the
// directive.
*/
extern const code_type_t ngx_mrb_code_forms[NGX_MRB_CODE_FORMS];

#define NGX_MRB_CODE_FORM_POST(form) ((void *)&ngx_mrb_code_forms[form])
#define NGX_MRB_CODE_FORM_OF(cmd) (*(const code_type_t *)(cmd)->post)

#endif /* NGX_MRUBY_CODE_H */
