# Hook script of test/conf/conf.d/67-var-input.conf (port 18153), for
# test/t/cases/var_input.rb. It makes the Nginx::Var call that the path of
# the request names and answers 200 with what happened:
#
#   "returned: VALUE"         the call returned VALUE (shown with inspect)
#   "raised: CLASS: MESSAGE"  the call raised, and this script rescued it
#
# A second line gives $var_input_target after the call. The server sets it to
# "initial" for each request. An exception that this script does not rescue
# answers 500, and a call that ends the nginx process leaves the request
# without an answer.
#
# The bad calls pass the name as a String, as code does that builds the name
# of a variable at run time.
v = Nginx::Var.new
path = Nginx::Request.new.uri

begin
  result =
    case path
    when '/get'
      v.var_input_target
    when '/get_uppercase'
      v.VAR_INPUT_TARGET
    when '/setter'
      v.send('var_input_target=', 'changed')
    when '/set'
      v.set('var_input_target', 'set')
    when '/set_frozen_key'
      key = 'Var_Input_Target'.freeze
      v.set(key, 'frozen key')
      [key.frozen?, key]
    when '/set_symbol_key'
      # A name of more than 27 bytes, the most that mruby keeps inside a
      # String object on a 64-bit build: Symbol#to_s shares the bytes of the
      # name that the mrb_state of the worker keeps for the Symbol.
      v.set(:Var_Input_Target_Set_By_A_Symbol, 'symbol key')
      [:Var_Input_Target_Set_By_A_Symbol.to_s, v.var_input_target_set_by_a_symbol]
    when '/set_shared_key'
      # Too long to be kept inside the String object, so dup shares the
      # bytes of name. No variable has this name.
      name = 'Var_Input_Target_' + 'Shared' * 6
      copy = name.dup
      v.set(copy, 'shared key')
      [name, copy]
    when '/realpath_root'
      v.realpath_root
    when '/empty_name'
      v.send('')
    when '/setter_without_value'
      v.send('var_input_target=')
    when '/equal_sign_only'
      v.send('=', 'x')
    when '/set_nul_value'
      sent = "ab" + 0.chr + "cd"
      v.var_input_target = sent
      got = v.var_input_target
      same = (got == sent)
      v.var_input_target = 'restored'
      [same, got.length]
    when '/set_nul_value_via_set'
      sent = "ab" + 0.chr + "cd"
      v.set('var_input_target', sent)
      got = v.var_input_target
      same = (got == sent)
      v.set('var_input_target', 'restored')
      [same, got.length]
    else
      raise "no call for #{path}"
    end
  Nginx.rputs "returned: #{result.inspect}\n"
rescue => e
  Nginx.rputs "raised: #{e.class}: #{e.message}\n"
end
Nginx.rputs "var_input_target: #{v.var_input_target.inspect}"
