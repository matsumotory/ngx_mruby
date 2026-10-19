/*
// ngx_http_mruby_var.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#include "ngx_http_mruby_var.h"

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_request.h"

#include <ngx_log.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/string.h>

/**
 * See the following page about nginx variables.
 * http://nginx.org/en/docs/varindex.html
 */

static mrb_value ngx_mrb_var_get(mrb_state *mrb, mrb_value self, const char *c_name, size_t c_len,
                                 ngx_http_request_t *r)
{
  ngx_http_variable_value_t *var;
  ngx_str_t ngx_name;

  ngx_uint_t key;

  ngx_name.len = c_len;
  ngx_name.data = (u_char *)c_name;

  key = ngx_hash_strlow(ngx_name.data, ngx_name.data, ngx_name.len);
  var = ngx_http_get_variable(r, &ngx_name, key);
  if (var == NULL) {
    // c_name has no NUL byte at its end: log c_len bytes of it
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %*s is NULL", MODULE_NAME, __func__, __LINE__,
                  c_len, c_name);
    return mrb_nil_value();
  }

  // return variable value wraped with mruby string
  if (!var->not_found) {
    return mrb_str_new(mrb, (char *)var->data, var->len);
  } else {
    return mrb_nil_value();
  }
}

mrb_value ngx_mrb_var_set(mrb_state *mrb, mrb_value self, char *k, mrb_value o, ngx_http_request_t *r)
{
  return ngx_mrb_var_set_vector(mrb, self, k, strlen(k), o, r);
}

mrb_value ngx_mrb_var_set_vector(mrb_state *mrb, mrb_value self, char *k, int len, mrb_value o, ngx_http_request_t *r)
{
  ngx_http_variable_t *v;
  ngx_http_variable_value_t *vv;
  ngx_http_core_main_conf_t *cmcf;
  ngx_str_t key;
  ngx_uint_t hash;
  ngx_str_t val;
  u_char *valp;

  if (mrb_type(o) != MRB_TT_STRING) {
    o = mrb_funcall(mrb, o, "to_s", 0, NULL);
  }

  val.data = (u_char *)RSTRING_PTR(o);
  val.len = RSTRING_LEN(o);
  key.len = len;
  key.data = (u_char *)k;

  /* RSTRING_PTR(o) is not always null-terminated */
  valp = ngx_palloc(r->pool, val.len + 1);
  if (valp == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    goto ARENA_RESTOR_AND_ERROR;
  }
  ngx_cpystrn(valp, val.data, val.len + 1);

  hash = ngx_hash_strlow(key.data, key.data, key.len);
  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  v = ngx_hash_find(&cmcf->variables_hash, hash, key.data, key.len);

  if (v) {
    if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s not changeable", MODULE_NAME, __func__,
                    __LINE__, k);
      goto ARENA_RESTOR_AND_ERROR;
    } else if (v->set_handler) {
      vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
      if (vv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME,
                      __func__, __LINE__);
        goto ARENA_RESTOR_AND_ERROR;
      }
      v->set_handler(r, vv, v->data);
    } else if (v->flags & NGX_HTTP_VAR_INDEXED) {
      vv = &r->variables[v->index];
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s is not assinged", MODULE_NAME, __func__,
                    __LINE__, k);
      goto ARENA_RESTOR_AND_ERROR;
    }
    vv->valid = 1;
    vv->not_found = 0;
    vv->no_cacheable = 0;
    vv->data = valp;
    vv->len = val.len;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: set variable key:%s val:%s", MODULE_NAME,
                  __func__, __LINE__, k, valp);
    return mrb_str_new(mrb, (char *)vv->data, vv->len);
  }

  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s is not found", MODULE_NAME, __func__, __LINE__,
                k);

ARENA_RESTOR_AND_ERROR:
  return mrb_nil_value();
}

/*
 * A method name that names no variable gets the NoMethodError that Ruby
 * raises for a method that the receiver does not have.
 */
static mrb_noreturn void ngx_mrb_var_no_variable_error(mrb_state *mrb, mrb_sym name, const mrb_value *a, mrb_int alen)
{
  mrb_no_method_error(mrb, name, mrb_ary_new_from_values(mrb, alen, a), "undefined method '%n' for Nginx::Var", name);
}

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self)
{
  mrb_sym name;
  mrb_int alen, len, start, end;
  mrb_value *a, s_name;
  const char *p;
  char *c_name;
  ngx_http_request_t *r;

  r = ngx_mrb_get_request_or_raise(mrb);

  // get var symble from method_missing(sym, *args)
  mrb_get_args(mrb, "n*", &name, &a, &alen);

  s_name = mrb_sym_str(mrb, name);
  p = RSTRING_PTR(s_name);
  len = RSTRING_LEN(s_name);

  if (len == 0) {
    ngx_mrb_var_no_variable_error(mrb, name, a, alen);
  }

  if (p[len - 1] != '=') {
    // Nginx::Var#<name>: the variable is the whole name
    c_name = ngx_pnalloc(r->pool, len);
    if (c_name == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                    __LINE__);
      return mrb_nil_value();
    }
    ngx_memcpy(c_name, p, len);
    return ngx_mrb_var_get(mrb, self, c_name, len, r);
  }

  /*
   * Nginx::Var#<name>=: the variable is the first run of characters other
   * than '=' and NUL in the name, the token that strtok(name, "=") returned
   * here before. A name made only of '=' has none.
   */
  for (start = 0; start < len && p[start] == '='; start++) {
    /* void */
  }
  if (start == len || p[start] == '\0') {
    ngx_mrb_var_no_variable_error(mrb, name, a, alen);
  }
  if (alen == 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong number of arguments (given %i, expected 1) for Nginx::Var#%n", alen, name);
  }
  // the name ends with '=', so this stops inside the name
  for (end = start; p[end] != '=' && p[end] != '\0'; end++) {
    /* void */
  }

  // ngx_mrb_var_set takes a name that ends with a NUL byte
  c_name = ngx_pnalloc(r->pool, end - start + 1);
  if (c_name == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    return mrb_nil_value();
  }
  ngx_memcpy(c_name, p + start, end - start);
  c_name[end - start] = '\0';

  return ngx_mrb_var_set(mrb, self, c_name, a[0], r);
}

static mrb_value ngx_mrb_var_exist(mrb_state *mrb, mrb_value self)
{
  mrb_int m_len;
  char *c_name;

  ngx_http_request_t *r;
  ngx_http_variable_value_t *var;
  ngx_str_t ngx_name;
  ngx_uint_t key;

  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "s", &c_name, &m_len);

  ngx_name.len = (size_t)m_len;
  ngx_name.data = ngx_palloc(r->pool, ngx_name.len);
  ngx_memcpy(ngx_name.data, (u_char *)c_name, ngx_name.len);

  key = ngx_hash_strlow(ngx_name.data, ngx_name.data, ngx_name.len);
  var = ngx_http_get_variable(r, &ngx_name, key);
  if (var != NULL && !var->not_found) {
    return mrb_true_value();
  }

  return mrb_false_value();
}

static mrb_value ngx_mrb_var_set_func(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r;
  ngx_http_variable_t *v;
  ngx_http_variable_value_t *vv;
  ngx_http_core_main_conf_t *cmcf;
  ngx_str_t key, val;
  ngx_uint_t hash;
  mrb_value k;
  mrb_value o;
  u_char *keyp, *lowkey, *valp;

  mrb_get_args(mrb, "oo", &k, &o);
  if (mrb_type(k) != MRB_TT_STRING) {
    k = mrb_funcall(mrb, k, "to_s", 0, NULL);
  }
  if (mrb_type(o) != MRB_TT_STRING) {
    o = mrb_funcall(mrb, o, "to_s", 0, NULL);
  }

  r = ngx_mrb_get_request_or_raise(mrb);

  key.data = (u_char *)RSTRING_PTR(k);
  key.len = RSTRING_LEN(k);
  val.data = (u_char *)RSTRING_PTR(o);
  val.len = RSTRING_LEN(o);

  /* RSTRING_PTR(k) is not always null-terminated */
  keyp = ngx_palloc(r->pool, key.len + 1);
  if (keyp == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    goto ARENA_RESTOR_AND_ERROR;
  }

  /* RSTRING_PTR(o) is not always null-terminated */
  valp = ngx_palloc(r->pool, val.len + 1);
  if (valp == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    goto ARENA_RESTOR_AND_ERROR;
  }

  /*
   * The lookup takes the lowercased name. Lowercase a copy: k is the
   * caller's String, which can be frozen or share its bytes with other
   * Strings, or the String of a Symbol, which can share the bytes of the
   * name that the mrb_state keeps for the Symbol.
   */
  lowkey = ngx_pnalloc(r->pool, key.len);
  if (lowkey == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                  __LINE__);
    goto ARENA_RESTOR_AND_ERROR;
  }

  ngx_cpystrn(keyp, key.data, key.len + 1);
  ngx_cpystrn(valp, val.data, val.len + 1);

  hash = ngx_hash_strlow(lowkey, key.data, key.len);
  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  v = ngx_hash_find(&cmcf->variables_hash, hash, lowkey, key.len);

  if (v) {
    if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s not changeable", MODULE_NAME, __func__,
                    __LINE__, keyp);
      goto ARENA_RESTOR_AND_ERROR;
    } else if (v->set_handler) {
      vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
      if (vv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME,
                      __func__, __LINE__);
        goto ARENA_RESTOR_AND_ERROR;
      }
      v->set_handler(r, vv, v->data);
    } else if (v->flags & NGX_HTTP_VAR_INDEXED) {
      vv = &r->variables[v->index];
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s is not assinged", MODULE_NAME, __func__,
                    __LINE__, keyp);
      goto ARENA_RESTOR_AND_ERROR;
    }
    vv->valid = 1;
    vv->not_found = 0;
    vv->no_cacheable = 0;
    vv->data = valp;
    vv->len = val.len;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: set variable key:%s val:%s", MODULE_NAME,
                  __func__, __LINE__, keyp, valp);
    return mrb_str_new(mrb, (char *)vv->data, vv->len);
  }

  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s is not found", MODULE_NAME, __func__, __LINE__,
                keyp);

ARENA_RESTOR_AND_ERROR:
  return mrb_nil_value();
}

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_var;

  class_var = mrb_define_class_under(mrb, class, "Var", mrb->object_class);
  mrb_define_method(mrb, class_var, "method_missing", ngx_mrb_var_method_missing, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_var, "exist?", ngx_mrb_var_exist, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_var, "set", ngx_mrb_var_set_func, MRB_ARGS_REQ(2));
}
