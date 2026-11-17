# Hook script of test/conf/conf.d/99-var-assign.conf (port 18107), for
# test/t/cases/var_assign.rb. The path of the request is
# /<call>/<name>[/rescue]:
#
#   <call>   setter: v.<name> = 42, through Nginx::Var#method_missing or the
#            accessor that it defined; set: v.set("<name>", 42)
#   <name>   the name of the variable as the script writes it
#   /rescue  the script rescues the exception of the assignment
#
# The value is the Integer 42, which the assignment converts with to_s. The
# script answers 200 with "returned=VALUE read=VALUE" (each shown with
# inspect): what the call returned, and the variable read back by its name
# in lowercase. With /rescue, an exception gives
# "raised: CLASS: MESSAGE". An exception that the script does not rescue
# answers 500.
v = Nginx::Var.new
_, call, name, rescue_it = Nginx::Request.new.uri.split('/')

assign = lambda do
  case call
  when 'setter'
    v.send("#{name}=", 42)
  when 'set'
    v.set(name, 42)
  else
    raise "no call #{call}"
  end
end

if rescue_it == 'rescue'
  begin
    assign.call
    Nginx.rputs 'returned'
  rescue => e
    Nginx.rputs "raised: #{e.class}: #{e.message}"
  end
else
  returned = assign.call
  Nginx.rputs "returned=#{returned.inspect} read=#{v.send(name.downcase).inspect}"
end
