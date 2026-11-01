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
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>

/**
 * See the following page about nginx variables.
 * http://nginx.org/en/docs/varindex.html
 */

/*
 * The names and hash keys of the variables that ngx_mruby's own methods read
 * (see NGX_MRB_VAR_LIST in ngx_http_mruby_var.h). The names are lowercase, so
 * the keys are those that ngx_hash_strlow() would give, and they depend on
 * nothing else: ngx_mrb_var_class_init() computes them once, before any
 * request.
 */
typedef struct {
  ngx_str_t name;
  ngx_uint_t key;
} ngx_mrb_var_fixed_t;

#define NGX_MRB_VAR_FIXED(id, name) {ngx_string(name), 0},
static ngx_mrb_var_fixed_t ngx_mrb_var_fixed[NGX_MRB_VAR_COUNT] = {NGX_MRB_VAR_LIST(NGX_MRB_VAR_FIXED)};
#undef NGX_MRB_VAR_FIXED

// name is the lowercase name of the variable, and key its hash key
static mrb_value ngx_mrb_var_get(mrb_state *mrb, ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t key)
{
  ngx_http_variable_value_t *var;

  var = ngx_http_get_variable(r, name, key);
  if (var == NULL) {
    // name has no NUL byte at its end: log name->len bytes of it
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: %V is NULL", MODULE_NAME, __func__, __LINE__,
                  name);
    return mrb_nil_value();
  }

  // return variable value wraped with mruby string
  if (!var->not_found) {
    return mrb_str_new(mrb, (char *)var->data, var->len);
  } else {
    return mrb_nil_value();
  }
}

mrb_value ngx_mrb_var_get_fixed(mrb_state *mrb, ngx_mrb_var_id_t id)
{
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);

  return ngx_mrb_var_get(mrb, r, &ngx_mrb_var_fixed[id].name, ngx_mrb_var_fixed[id].key);
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

  // The value as a String: mrb_obj_as_string() keeps a to_s that does not
  // return a String from reaching RSTRING_PTR. Called from C code (when the
  // fiber of an mruby_set handler has returned), an exception of to_s comes
  // back in mrb->exc; the caller logs it and answers 500.
  o = mrb_obj_as_string(mrb, o);
  if (mrb->exc != NULL) {
    return mrb_nil_value();
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
  /* copy the whole value; ngx_cpystrn stops at an embedded NUL and would leave
   * the rest of valp uninitialised while vv->len keeps the full length */
  ngx_memcpy(valp, val.data, val.len);
  valp[val.len] = '\0';

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

/*
 * v.NAME and v.NAME = value, for the method name name and its arguments:
 * what Nginx::Var#method_missing does, and what the accessors that it
 * defines do.
 */
static mrb_value ngx_mrb_var_access(mrb_state *mrb, mrb_value self, ngx_http_request_t *r, mrb_sym name,
                                    const mrb_value *a, mrb_int alen)
{
  mrb_int len, start, end;
  const char *p;
  char *c_name;
  ngx_str_t ngx_name;
  ngx_uint_t key;

  /*
   * p is the name that the mrb_state keeps for the symbol, or a buffer of
   * the mrb_state for a short name, which the next call of
   * mrb_sym_name_len() overwrites: it is copied before any other call.
   */
  p = mrb_sym_name_len(mrb, name, &len);

  if (p == NULL || len == 0) {
    ngx_mrb_var_no_variable_error(mrb, name, a, alen);
  }

  if (p[len - 1] != '=') {
    // Nginx::Var#<name>: the variable is the whole name, looked up in
    // lowercase
    c_name = ngx_pnalloc(r->pool, len);
    if (c_name == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s ERROR %s:%d: memory allocate failed", MODULE_NAME, __func__,
                    __LINE__);
      return mrb_nil_value();
    }
    ngx_memcpy(c_name, p, len);
    ngx_name.len = len;
    ngx_name.data = (u_char *)c_name;
    key = ngx_hash_strlow(ngx_name.data, ngx_name.data, ngx_name.len);
    return ngx_mrb_var_get(mrb, r, &ngx_name, key);
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

/*
 * An accessor that Nginx::Var#method_missing defined: the variable is the
 * name that the method was called with.
 */
static mrb_value ngx_mrb_var_accessor(mrb_state *mrb, mrb_value self)
{
  const mrb_value *a;
  mrb_int alen;
  ngx_http_request_t *r;

  r = ngx_mrb_get_request_or_raise(mrb);

  // "!": the arguments are read where they are, without a copy into an Array
  mrb_get_args(mrb, "*!", &a, &alen);

  return ngx_mrb_var_access(mrb, self, r, mrb_get_mid(mrb), a, alen);
}

/*
 * After method_missing has served an access, it defines an accessor of the
 * method name on Nginx::Var, so that the next access of the name in the
 * worker finds a method instead of searching every ancestor of Nginx::Var
 * for a name that none of them has. The methods stay in the mrb_state of
 * the worker, which every later request of the worker shares, so only
 * names of variables get one, and their number is bounded:
 *
 * - The name, without the '=' at the end of a setter, is made only of the
 *   characters of a variable name in nginx.conf in lowercase (a to z, 0 to
 *   9, '_'). The lookup lowercases the name, so every spelling of a name
 *   reads the same variable; a spelling with an uppercase letter keeps
 *   working through method_missing and gets no method.
 * - A getter or a setter of a declared variable (the variables of nginx and
 *   its modules, and those that set declares: cmcf->variables_hash). The
 *   configuration fixes these names.
 * - A getter of a prefix variable (arg_, http_, cookie_ and the other
 *   families of cmcf->prefix_variables), for the first
 *   NGX_HTTP_MRUBY_VAR_PREFIX_ACCESSORS_MAX such names of the worker: a
 *   prefix takes any suffix, so these names are as many as the requests
 *   choose. A setter of such a name finds no variable
 *   (ngx_mrb_var_set_vector assigns only declared variables) and gets none.
 * - Nothing for a name that is not a variable.
 *
 * No method is defined when the receiver is not an instance of Nginx::Var
 * itself (a subclass, or a class that a script put in its place), when
 * Nginx::Var is frozen, or when Nginx::Var or an ancestor has a method of
 * the name already, which happens only when method_missing is called
 * directly: an accessor would hide that method, such as Kernel#server_name.
 */
static void ngx_mrb_var_define_accessor(mrb_state *mrb, mrb_value self, ngx_http_request_t *r, mrb_sym name)
{
  ngx_http_mruby_main_conf_t *mmcf;
  ngx_http_core_main_conf_t *cmcf;
  ngx_http_variable_t *pv;
  struct RClass *c;
  const char *p;
  mrb_int len, vlen, i;
  ngx_uint_t key, n;
  ngx_flag_t prefix;
  u_char ch;

  mmcf = ngx_http_get_module_main_conf(r, ngx_http_mruby_module);
  c = mrb_obj_class(mrb, self);
  // var_class is only compared: c is alive, because self is
  if (c != mmcf->var_class || mrb_frozen_p(c)) {
    return;
  }

  p = mrb_sym_name_len(mrb, name, &len);
  if (p == NULL || len == 0) {
    return;
  }
  vlen = (p[len - 1] == '=') ? len - 1 : len;
  if (vlen == 0) {
    return;
  }
  key = 0;
  for (i = 0; i < vlen; i++) {
    ch = (u_char)p[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) {
      return;
    }
    key = ngx_hash(key, ch);
  }

  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  prefix = 0;
  if (ngx_hash_find(&cmcf->variables_hash, key, (u_char *)p, vlen) == NULL) {
    if (vlen != len || mmcf->var_prefix_accessors >= NGX_HTTP_MRUBY_VAR_PREFIX_ACCESSORS_MAX) {
      return;
    }
    pv = cmcf->prefix_variables.elts;
    for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
      if ((size_t)vlen >= pv[n].name.len && ngx_strncmp(p, pv[n].name.data, pv[n].name.len) == 0) {
        break;
      }
    }
    if (n == cmcf->prefix_variables.nelts) {
      return;
    }
    prefix = 1;
  }

  if (mrb_obj_respond_to(mrb, c, name)) {
    return;
  }

  mrb_define_method_id(mrb, c, name, ngx_mrb_var_accessor, MRB_ARGS_ANY());
  if (prefix) {
    mmcf->var_prefix_accessors++;
  }
}

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self)
{
  mrb_sym name;
  mrb_int alen;
  const mrb_value *a;
  mrb_value result;
  ngx_http_request_t *r;

  r = ngx_mrb_get_request_or_raise(mrb);

  // get var symble from method_missing(sym, *args)
  mrb_get_args(mrb, "n*", &name, &a, &alen);

  result = ngx_mrb_var_access(mrb, self, r, name, a, alen);
  ngx_mrb_var_define_accessor(mrb, self, r, name);

  return result;
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
  // mrb_obj_as_string() gives a String also when to_s returns another object
  k = mrb_obj_as_string(mrb, k);
  o = mrb_obj_as_string(mrb, o);

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
  /* copy the whole value; ngx_cpystrn stops at an embedded NUL and would leave
   * the rest of valp uninitialised while vv->len keeps the full length */
  ngx_memcpy(valp, val.data, val.len);
  valp[val.len] = '\0';

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
  ngx_uint_t i;

  for (i = 0; i < NGX_MRB_VAR_COUNT; i++) {
    ngx_mrb_var_fixed[i].key = ngx_hash_key(ngx_mrb_var_fixed[i].name.data, ngx_mrb_var_fixed[i].name.len);
  }

  class_var = mrb_define_class_under(mrb, class, "Var", mrb->object_class);
  mrb_define_method(mrb, class_var, "method_missing", ngx_mrb_var_method_missing, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_var, "exist?", ngx_mrb_var_exist, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_var, "set", ngx_mrb_var_set_func, MRB_ARGS_REQ(2));
}
