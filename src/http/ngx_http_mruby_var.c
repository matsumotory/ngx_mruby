/*
// ngx_http_mruby_var.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#include "ngx_http_mruby_var.h"

#include "ngx_log.h"
#include <mruby.h>
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

  size_t len;
  ngx_uint_t key;

  ngx_name.len = c_len;
  ngx_name.data = (u_char *)c_name;
  len = ngx_name.len;

  key = ngx_hash_strlow(ngx_name.data, ngx_name.data, len);
  var = ngx_http_get_variable(r, &ngx_name, key);
  if (var == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %s is NULL", MODULE_NAME, __func__, __LINE__,
                  c_name);
    return mrb_nil_value();
  }

  // return variable value wraped with mruby string
  if (!var->not_found) {
    return mrb_str_new(mrb, (char *)var->data, var->len);
  } else {
    return mrb_nil_value();
  }
}

static mrb_value ngx_mrb_var_set(mrb_state *mrb, mrb_value self, char *k, mrb_value o, ngx_http_request_t *r)
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
  key.len = strlen(k);
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
  r = ngx_mrb_get_request();
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

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self)
{
  mrb_value name, *a;
  int alen, c_len;
  mrb_value s_name;
  char *c_name;
  ngx_http_request_t *r;

  r = ngx_mrb_get_request();

  // get var symble from method_missing(sym, *args)
  mrb_get_args(mrb, "n*", &name, &a, &alen);

  // name is a symble obj
  // first init name with mrb_symbol
  // second get mrb_string with mrb_sym2str
  s_name = mrb_sym2str(mrb, mrb_symbol(name));
  c_len = RSTRING_LEN(s_name);
  c_name = ngx_palloc(r->pool, c_len);
  ngx_memcpy(c_name, RSTRING_PTR(s_name), c_len);

  if (c_name[c_len - 1] == '=') {
    return ngx_mrb_var_set(mrb, self, strtok(c_name, "="), a[0], r);
  } else {
    return ngx_mrb_var_get(mrb, self, c_name, c_len, r);
  }
}

static mrb_value ngx_mrb_var_exist(mrb_state *mrb, mrb_value self)
{
  mrb_int m_len;
  char *c_name;

  ngx_http_request_t *r;
  ngx_http_variable_value_t *var;
  ngx_str_t ngx_name;
  ngx_uint_t key;

  r = ngx_mrb_get_request();

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
  u_char *keyp, *valp;

  mrb_get_args(mrb, "oo", &k, &o);
  if (mrb_type(k) != MRB_TT_STRING) {
    k = mrb_funcall(mrb, k, "to_s", 0, NULL);
  }
  if (mrb_type(o) != MRB_TT_STRING) {
    o = mrb_funcall(mrb, o, "to_s", 0, NULL);
  }

  r = ngx_mrb_get_request();

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

  ngx_cpystrn(keyp, key.data, key.len + 1);
  ngx_cpystrn(valp, val.data, val.len + 1);

  hash = ngx_hash_strlow(key.data, key.data, key.len);
  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  v = ngx_hash_find(&cmcf->variables_hash, hash, key.data, key.len);

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
