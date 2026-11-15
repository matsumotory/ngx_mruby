/*
// ngx_mruby_code.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

/*
// The code of a directive and its compile, shared by the http module
// (src/http/ngx_http_mruby_module.c) and the stream module
// (src/stream/ngx_stream_mruby_module.c). See ngx_mruby_code.h.
*/

#include "ngx_mruby_code.h"
#include "ngx_mruby_fiber.h"
#include "../http/ngx_http_mruby_gc_roots.h"

#include <mruby/proc.h>

static ngx_mrb_code_t *ngx_mrb_code_new(ngx_pool_t *pool, ngx_str_t *source, code_type_t type)
{
  ngx_mrb_code_t *code;
  char *p;

  code = ngx_pcalloc(pool, sizeof(*code));
  if (code == NULL) {
    return NGX_CONF_UNSET_PTR;
  }

  p = ngx_palloc(pool, source->len + 1);
  if (p == NULL) {
    return NGX_CONF_UNSET_PTR;
  }
  ngx_cpystrn((u_char *)p, source->data, source->len + 1);

  if (type == NGX_MRB_CODE_TYPE_FILE) {
    code->code.file = p;
    code->cache = 0;
  } else {
    code->code.string = p;
    code->cache = 1;
  }
  code->code_type = type;
  code->slot = NGX_MRB_GC_ROOTS_NONE;

  return code;
}

ngx_mrb_code_t *ngx_mrb_code_from_file(ngx_pool_t *pool, ngx_str_t *path)
{
  return ngx_mrb_code_new(pool, path, NGX_MRB_CODE_TYPE_FILE);
}

ngx_mrb_code_t *ngx_mrb_code_from_string(ngx_pool_t *pool, ngx_str_t *string)
{
  return ngx_mrb_code_new(pool, string, NGX_MRB_CODE_TYPE_STRING);
}

/*
// Puts proc in the slot of code: the previous proc leaves the slot, and the
// new one takes it. Removing first puts the slot at the head of the free list
// of the holder, so the second call takes the same slot without growing the
// holder, and cannot raise.
*/
static ngx_int_t ngx_mrb_code_hold(mrb_state *mrb, ngx_mrb_code_t *code, mrb_value proc)
{
  ngx_mrb_gc_roots_remove(mrb, code->slot);
  code->slot = ngx_mrb_gc_roots_add(mrb, proc);

  return code->slot == NGX_MRB_GC_ROOTS_NONE ? NGX_ERROR : NGX_OK;
}

/*
// Reads code with a new compiler context into a proc, without running it.
// fp is the open file of a file code, or NULL for a string code.
*/
static mrb_value ngx_mrb_code_load(mrb_state *mrb, ngx_mrb_code_t *code, FILE *fp)
{
  mrb_value proc;

  NGX_MRUBY_CODE_MRBC_CONTEXT_FREE(mrb, code);
  code->ctx = mrbc_context_new(mrb);
  code->ctx->no_exec = TRUE;
#ifdef NGX_MRUBY_IREP_DEBUG
  code->ctx->dump_result = TRUE;
#endif

  if (fp != NULL) {
    mrbc_filename(mrb, code->ctx, code->code.file);
    proc = mrb_load_file_cxt(mrb, fp, code->ctx);
  } else {
    mrbc_filename(mrb, code->ctx, "INLINE CODE");
    proc = mrb_load_string_cxt(mrb, code->code.string, code->ctx);
  }

  return proc;
}

ngx_int_t ngx_mrb_code_compile(ngx_conf_t *cf, mrb_state *mrb, ngx_mrb_code_t *code, const char *module_name,
                               const char *func)
{
  FILE *fp = NULL;
  mrb_value proc;
  ngx_int_t rc;
  int ai;

  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    fp = fopen(code->code.file, "r");
    if (fp == NULL) {
      return NGX_ERROR;
    }
  }

  ai = mrb_gc_arena_save(mrb);
  proc = ngx_mrb_code_load(mrb, code, fp);
  if (fp != NULL) {
    fclose(fp);
  }

  if (!mrb_proc_p(proc)) {
    mrb_gc_arena_restore(mrb, ai);
    return NGX_ERROR;
  }

  code->proc = mrb_proc_ptr(proc);
  ngx_mrb_fiber_prepare_proc(mrb, code->proc);
#ifdef NGX_MRUBY_IREP_DEBUG
  /* mrb_codedump_all() is not declared in mruby headers. So just follows the mruby way. See mruby/src/load.c. */
  void mrb_codedump_all(mrb_state *, struct RProc *);
  mrb_codedump_all(mrb, code->proc);
#endif

  rc = ngx_mrb_code_hold(mrb, code, proc);
  mrb_gc_arena_restore(mrb, ai);
  if (rc != NGX_OK) {
    return NGX_ERROR;
  }

  /* A debugging aid for each directive, logged while nginx reads the
     configuration through its startup log, which error_log cannot filter. */
  if (code->code_type == NGX_MRB_CODE_TYPE_FILE) {
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "%s INFO %s: compile info: code->code.file=(%s) code->cache=(%d)",
                       module_name, func, code->code.file, code->cache);
  } else {
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                       "%s INFO %s: compile info: "
                       "code->code.string=(%s) code->cache=(%d)",
                       module_name, func, code->code.string, code->cache);
  }

  return NGX_OK;
}

ngx_int_t ngx_mrb_code_reload(mrb_state *mrb, ngx_mrb_code_t *code)
{
  FILE *fp;
  mrb_value proc;

  fp = fopen(code->code.file, "r");
  if (fp == NULL) {
    return NGX_ERROR;
  }

  proc = ngx_mrb_code_load(mrb, code, fp);
  fclose(fp);

  if (!mrb_proc_p(proc)) {
    return NGX_ERROR;
  }

  code->proc = mrb_proc_ptr(proc);
  ngx_mrb_fiber_prepare_proc(mrb, code->proc);

  if (code->slot != NGX_MRB_GC_ROOTS_NONE) {
    return ngx_mrb_code_hold(mrb, code, proc);
  }

  return NGX_OK;
}
