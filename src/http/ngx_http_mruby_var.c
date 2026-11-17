/*
// ngx_http_mruby_var.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#include "ngx_http_mruby_var.h"

#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_core.h"

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
  ngx_http_request_t *r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Var#");

  return ngx_mrb_var_get(mrb, r, &ngx_mrb_var_fixed[id].name, ngx_mrb_var_fixed[id].key);
}

static mrb_value ngx_mrb_var_to_s(mrb_state *mrb, void *userdata)
{
  mrb_value v = mrb_funcall_id(mrb, *(mrb_value *)userdata, MRB_SYM(to_s), 0);

  return mrb_ensure_string_type(mrb, v);
}

mrb_bool ngx_mrb_var_to_string(mrb_state *mrb, mrb_value o, mrb_value *out)
{
  mrb_bool failed;

  if (mrb_string_p(o)) {
    *out = o;
    return TRUE;
  }
  *out = mrb_protect_error(mrb, ngx_mrb_var_to_s, &o, &failed);
  return !failed;
}

/*
 * What the set directive does (ngx_http_script_set_var_code and
 * ngx_http_script_var_set_handler_code), for a variable that Ruby code names
 * while the request runs. The checks that nginx makes when it reads a set
 * directive (ngx_http_rewrite_set, ngx_http_add_variable) are made here per
 * assignment, and their failures raise.
 */
mrb_value ngx_mrb_var_assign(mrb_state *mrb, ngx_http_request_t *r, const u_char *name, size_t len, mrb_value value)
{
  ngx_http_core_main_conf_t *cmcf;
  ngx_http_variable_t *v;
  ngx_http_variable_value_t *vv;
  ngx_uint_t hash;
  u_char *copy, *low, *data;
  size_t vlen;

  /*
   * The name as the caller gave it, for the messages, and in lowercase, for
   * the lookup. Both are copied before the conversion of the value runs Ruby
   * code, which can change the String or the buffer that name points to.
   */
  copy = ngx_pnalloc(r->pool, len * 2);
  if (copy == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  ngx_memcpy(copy, name, len);
  low = copy + len;
  hash = ngx_hash_strlow(low, copy, len);

  // the exception of a to_s that is missing, raises or returns no String
  if (!ngx_mrb_var_to_string(mrb, value, &value)) {
    mrb_exc_raise(mrb, value);
  }

  cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  v = ngx_hash_find(&cmcf->variables_hash, hash, low, len);

  if (v == NULL) {
    mrb_raisef(mrb, E_NAME_ERROR, "nginx variable $%l is not defined (declare it with set or mruby_variable)",
               (const char *)copy, len);
  }

  if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "nginx variable $%l cannot be changed by a script", (const char *)copy, len);
  }

  // set gives a variable without a set_handler an index when nginx reads
  // the configuration; a variable that nothing in the configuration refers
  // to has none, so the request has no place for its value
  if (v->set_handler == NULL && !(v->flags & NGX_HTTP_VAR_INDEXED)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR,
               "nginx variable $%l cannot be assigned by a script: the configuration does not refer to it",
               (const char *)copy, len);
  }

  /*
   * The value lives as long as the request: a copy in its pool, with a NUL
   * byte after it for the line of the info level below. The whole value is
   * copied, also past a NUL byte in it.
   */
  vlen = RSTRING_LEN(value);
  data = ngx_pnalloc(r->pool, vlen + 1);
  if (data == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  ngx_memcpy(data, RSTRING_PTR(value), vlen);
  data[vlen] = '\0';

  if (v->set_handler) {
    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
  } else {
    vv = &r->variables[v->index];
  }

  /*
   * Every field of the value is set before a set_handler reads it, as nginx
   * passes the set_handler a value that the script engine filled: a
   * set_handler such as that of $args or $limit_rate reads len and data.
   */
  vv->len = vlen;
  vv->valid = 1;
  vv->no_cacheable = 0;
  vv->not_found = 0;
  vv->escape = 0;
  vv->data = data;

  if (v->set_handler) {
    v->set_handler(r, vv, v->data);
  }

  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "%s INFO %s:%d: set variable key:%*s val:%s", MODULE_NAME,
                __func__, __LINE__, len, copy, data);

  return mrb_str_new(mrb, (char *)vv->data, vv->len);
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

  // ngx_mrb_var_assign copies the name before it runs any Ruby code
  return ngx_mrb_var_assign(mrb, r, (const u_char *)p + start, end - start, a[0]);
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

  r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Var#");

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
 *   (ngx_mrb_var_assign raises NameError for a name that is not declared)
 *   and gets none.
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

  r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Var#");

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

  r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Var#");

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
  mrb_value k;
  mrb_value o;

  mrb_get_args(mrb, "oo", &k, &o);
  // a name or a value that cannot be converted to a String raises
  if (!ngx_mrb_var_to_string(mrb, k, &k) || !ngx_mrb_var_to_string(mrb, o, &o)) {
    mrb_exc_raise(mrb, mrb_string_p(k) ? o : k);
  }

  r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Var#");

  // ngx_mrb_var_assign looks the variable up by a lowercased copy of the
  // name, and leaves the String k as it is
  return ngx_mrb_var_assign(mrb, r, (const u_char *)RSTRING_PTR(k), RSTRING_LEN(k), o);
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

/*
 * mruby_variable $name [value];
 *
 * Declares $name in the http {} block as a changeable, indexed variable that
 * scripts assign with Nginx::Var, without a "set" that runs in a phase of
 * the request. Each declaration has one ngx_http_mruby_variable_t, allocated
 * on its own so that its address, which the variable keeps as the data of
 * its get handler, does not move. mmcf->variables holds the pointers, so
 * that ngx_http_mruby_variables_check() finds the declarations again.
 */
typedef struct {
  ngx_http_variable_t *var;
  // the value of the variable before a script assigns it; NULL for ""
  ngx_http_complex_value_t *value;
  // where the directive is, for the message of the check
  ngx_str_t file;
  ngx_uint_t line;
} ngx_http_mruby_variable_t;

/*
 * The reason that the directive and its check give for a changeable
 * variable that has a get handler of another module, which is either a
 * module with a value of its own or a named capture of a regular
 * expression.
 */
#define NGX_HTTP_MRUBY_VARIABLE_OTHER                                                                                  \
  "another module defines it with a value of its own, or a named capture of a regular expression assigns it"

/*
 * The get handler of a declared variable. nginx calls it only while the
 * request has no value for the variable: an assignment through Nginx::Var
 * or "set" writes r->variables[index], and nginx then returns that value
 * without calling the handler. nginx keeps the value computed here in the
 * same place, so it is computed once per request at most.
 */
static ngx_int_t ngx_http_mruby_variable_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
  ngx_http_mruby_variable_t *mv = (ngx_http_mruby_variable_t *)data;
  ngx_str_t value;

  if (mv->value == NULL) {
    *v = ngx_http_variable_null_value;
    return NGX_OK;
  }

  if (ngx_http_complex_value(r, mv->value, &value) != NGX_OK) {
    return NGX_ERROR;
  }

  v->len = value.len;
  v->data = value.data;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  return NGX_OK;
}

/*
 * Whether the get handler of v only stands for a variable that a directive
 * assigns while the request runs, so that the variable has no value of its
 * own: the handler of "set", and that of the directives of ngx_devel_kit
 * such as mruby_set, which only log that the variable is not set yet. Both
 * keep the index of the variable as the data of the handler, which a
 * handler of a module with a value of its own does not do.
 */
static ngx_flag_t ngx_http_mruby_variable_only_assigned(ngx_http_core_main_conf_t *cmcf, ngx_http_variable_t *v)
{
  ngx_http_variable_t *indexed;

  if (v->data >= cmcf->variables.nelts) {
    return 0;
  }

  indexed = cmcf->variables.elts;
  indexed = &indexed[v->data];

  return indexed->name.len == v->name.len && ngx_strncmp(indexed->name.data, v->name.data, v->name.len) == 0;
}

char *ngx_http_mruby_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_mruby_main_conf_t *mmcf = conf;
  ngx_http_core_main_conf_t *cmcf;
  ngx_http_mruby_variable_t *mv, **slot;
  ngx_http_compile_complex_value_t ccv;
  ngx_http_variable_t *v, *pv;
  ngx_hash_key_t *key;
  ngx_str_t *value, name;
  ngx_uint_t i;

  value = cf->args->elts;

  if (value[1].len < 2 || value[1].data[0] != '$') {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
  }

  name.len = value[1].len - 1;
  name.data = value[1].data + 1;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  // $http_<name>, $arg_<name>, $cookie_<name> and the like: nginx gives
  // them their values from the name, and a declaration would hide them
  pv = cmcf->prefix_variables.elts;
  for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
    if (name.len >= pv[i].name.len && ngx_strncasecmp(name.data, pv[i].name.data, pv[i].name.len) == 0) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "mruby_variable cannot declare \"%V\": nginx gives the variables whose names begin with "
                         "\"%V\" their values",
                         &value[1], &pv[i].name);
      return NGX_CONF_ERROR;
    }
  }

  // A variable that an earlier directive or a module declared: refused
  // when it has a value of its own, accepted when "set" or a directive of
  // ngx_devel_kit only assigns it
  key = cmcf->variables_keys->keys.elts;
  for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
    if (name.len != key[i].key.len || ngx_strncasecmp(name.data, key[i].key.data, name.len) != 0) {
      continue;
    }

    v = key[i].value;

    if (v->get_handler == ngx_http_mruby_variable_get) {
      mv = (ngx_http_mruby_variable_t *)v->data;
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mruby_variable \"%V\" is duplicate: it is declared in %V:%ui",
                         &value[1], &mv->file, mv->line);
      return NGX_CONF_ERROR;
    }

    if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "mruby_variable cannot declare \"%V\": another module defines it with a value of its own",
                         &value[1]);
      return NGX_CONF_ERROR;
    }

    // A changeable variable with a get handler of another kind: a module
    // with a value of its own ($args, map, geo), or a named capture of a
    // regular expression, whose get handler nginx keeps static, so that
    // the two cannot be told apart here
    if (v->get_handler != NULL && !ngx_http_mruby_variable_only_assigned(cmcf, v)) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mruby_variable cannot declare \"%V\": " NGX_HTTP_MRUBY_VARIABLE_OTHER,
                         &value[1]);
      return NGX_CONF_ERROR;
    }

    break;
  }

  v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
  if (v == NULL) {
    return NGX_CONF_ERROR;
  }

  // the index makes it an indexed variable, which Nginx::Var assigns in
  // r->variables
  if (ngx_http_get_variable_index(cf, &name) == NGX_ERROR) {
    return NGX_CONF_ERROR;
  }

  mv = ngx_pcalloc(cf->pool, sizeof(ngx_http_mruby_variable_t));
  if (mv == NULL) {
    return NGX_CONF_ERROR;
  }

  mv->var = v;
  mv->file = cf->conf_file->file.name;
  mv->line = cf->conf_file->line;

  if (cf->args->nelts == 3) {
    mv->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (mv->value == NULL) {
      return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = mv->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
  }

  if (mmcf->variables == NULL) {
    mmcf->variables = ngx_array_create(cf->pool, 4, sizeof(ngx_http_mruby_variable_t *));
    if (mmcf->variables == NULL) {
      return NGX_CONF_ERROR;
    }
  }

  slot = ngx_array_push(mmcf->variables);
  if (slot == NULL) {
    return NGX_CONF_ERROR;
  }
  *slot = mv;

  v->get_handler = ngx_http_mruby_variable_get;
  v->data = (uintptr_t)mv;

  return NGX_CONF_OK;
}

ngx_int_t ngx_http_mruby_variables_check(ngx_conf_t *cf, ngx_http_mruby_main_conf_t *mmcf)
{
  ngx_http_mruby_variable_t **mv;
  ngx_uint_t i;

  if (mmcf->variables == NULL) {
    return NGX_OK;
  }

  // A module that declares the variable after mruby_variable, such as
  // map, and a later named capture of a regular expression replace the get
  // handler without a check of their own
  mv = mmcf->variables->elts;
  for (i = 0; i < mmcf->variables->nelts; i++) {
    if (mv[i]->var->get_handler != ngx_http_mruby_variable_get || mv[i]->var->data != (uintptr_t)mv[i]) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "mruby_variable cannot declare \"$%V\" in %V:%ui: " NGX_HTTP_MRUBY_VARIABLE_OTHER,
                    &mv[i]->var->name, &mv[i]->file, mv[i]->line);
      return NGX_ERROR;
    }
  }

  return NGX_OK;
}
