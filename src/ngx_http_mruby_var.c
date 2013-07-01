/*
// ngx_http_mruby_var.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_var.c
*/

#include "ngx_http_mruby_var.h"

#include <mruby.h>
#include <mruby/string.h>

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_var_get(mrb_state *mrb, mrb_value self, const char *c_name);

void ngx_mrb_var_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_var;

  class_var = mrb_define_class_under(mrb, class, "Var", mrb->object_class);
  mrb_define_method(mrb, class_var, "method_missing", ngx_mrb_var_method_missing, ARGS_ANY());
}

static mrb_value ngx_mrb_var_get(mrb_state *mrb, mrb_value self, const char *c_name)
{
  ngx_http_request_t *r;
  ngx_http_variable_value_t *var;
  ngx_str_t ngx_name;

  u_char *low;
  size_t len;
  ngx_uint_t key;

  // get ngx_http_request_t
  r = ngx_mrb_get_request();

  // ngx_str_set(&ngx_name, c_name);
  ngx_name.len  = strlen(c_name);
  ngx_name.data = (u_char *)c_name;
  len           = ngx_name.len;
  // check alloced memory
  if (len) {
    low = ngx_pnalloc(r->pool, len);
    if (low == NULL) {
      return mrb_nil_value();
    }
  } else {
        return mrb_nil_value();
  }
  // get variable with c string from nginx
  key = ngx_hash_strlow(low, ngx_name.data, len);
  var = ngx_http_get_variable(r, &ngx_name, key);

  // return variable value wraped with mruby string
  if (!var->not_found)
    return mrb_str_new(mrb, (char *)var->data, var->len);
  else
    return mrb_nil_value();
}

static mrb_value ngx_mrb_var_method_missing(mrb_state *mrb, mrb_value self)
{
  mrb_value name, *a;
  int alen;
  mrb_value s_name;
  char *c_name;

  // get var symble from method_missing(sym, *args)
  mrb_get_args(mrb, "n*", &name, &a, &alen);

  // name is a symble obj
  // first init name with mrb_symbol
  // second get mrb_string with mrb_sym2str
  s_name = mrb_sym2str(mrb, mrb_symbol(name));
  c_name = mrb_str_to_cstr(mrb, s_name);

  return ngx_mrb_var_get(mrb, self, c_name);
}
