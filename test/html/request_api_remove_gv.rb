# Hook for location /g1/gv/remove in test/conf/conf.d/10-request-api.conf.
# Nginx.remove_global_variable takes a Symbol or a String name and returns
# the list of global variables that remain.
$g1_by_symbol = "s"
$g1_by_string = "t"
before = global_variables.include?(:$g1_by_symbol) && global_variables.include?(:$g1_by_string)
after_symbol = Nginx.remove_global_variable(:$g1_by_symbol)
after_string = Nginx.remove_global_variable("$g1_by_string")
Nginx.rputs [
  before,
  after_symbol.class,
  after_symbol.include?(:$g1_by_symbol),
  after_symbol.include?(:$g1_by_string),
  after_string.include?(:$g1_by_string),
  $g1_by_symbol.inspect,
  $g1_by_string.inspect,
].join("|")
