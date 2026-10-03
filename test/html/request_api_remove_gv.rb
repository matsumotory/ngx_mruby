# Hook for location /request_api/gv/remove in test/conf/conf.d/10-request-api.conf.
# Nginx.remove_global_variable takes a Symbol or a String name and returns
# the list of global variables that remain.
$request_api_by_symbol = "s"
$request_api_by_string = "t"
before = global_variables.include?(:$request_api_by_symbol) && global_variables.include?(:$request_api_by_string)
after_symbol = Nginx.remove_global_variable(:$request_api_by_symbol)
after_string = Nginx.remove_global_variable("$request_api_by_string")
Nginx.rputs [
  before,
  after_symbol.class,
  after_symbol.include?(:$request_api_by_symbol),
  after_symbol.include?(:$request_api_by_string),
  after_string.include?(:$request_api_by_string),
  $request_api_by_symbol.inspect,
  $request_api_by_string.inspect,
].join("|")
