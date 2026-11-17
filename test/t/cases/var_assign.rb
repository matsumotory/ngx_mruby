# Assignments to nginx variables: Nginx::Var#<name>=, Nginx::Var#set and the
# end of an mruby_set handler give a variable the same value, and an
# assignment to a variable that nginx does not know raises NameError, one to
# a variable that nginx does not let scripts change raises RuntimeError
# (decision 3 of docs/proposals/core-alpha1.md). A handler that does not
# rescue the exception answers 500, and error.log has the exception.
# Config: test/conf/conf.d/99-var-assign.conf (port 18107). Hook script:
# test/html/var_assign.rb, which assigns the Integer 42.

t = SimpleTest.new "ngx_mruby test: assignments of Nginx::Var"

def var_assign(path)
  HttpRequest.new.get base(18107) + path
end

def var_assign_log_path
  File.join(ENV['NGINX_INSTALL_DIR'], 'logs', 'error.log')
end

# The lines that error.log gets from offset on.
def var_assign_log_lines_from(offset)
  File.open(var_assign_log_path) do |f|
    f.seek(offset)
    f.read.to_s.split("\n")
  end
end

VAR_ASSIGN_NO_SUCH = 'nginx variable $%s is not defined (declare it with set or mruby_variable)'
VAR_ASSIGN_NOT_CHANGEABLE = 'nginx variable $%s cannot be changed by a script'
VAR_ASSIGN_NO_VALUE = 'nginx variable $%s cannot be assigned by a script: the configuration does not refer to it'

# Each assignment that a handler does not rescue: the path, the class and the
# message of the exception.
[
  ['/setter/var_assign_no_such', 'NameError', VAR_ASSIGN_NO_SUCH % 'var_assign_no_such'],
  ['/set/var_assign_no_such', 'NameError', VAR_ASSIGN_NO_SUCH % 'var_assign_no_such'],
  ['/setter/uri', 'RuntimeError', VAR_ASSIGN_NOT_CHANGEABLE % 'uri'],
  ['/set/uri', 'RuntimeError', VAR_ASSIGN_NOT_CHANGEABLE % 'uri'],
  ['/set/var_assign_mapped', 'RuntimeError', VAR_ASSIGN_NO_VALUE % 'var_assign_mapped'],
].each do |path, klass, message|
  t.assert("Nginx::Var - #{path.split('/')[1]} of #{path.split('/')[2]} raises #{klass}, which answers 500 and goes to error.log", "GET #{path} on 18107") do
    offset = File.size(var_assign_log_path)
    res = var_assign(path)
    t.assert_equal 500, res.code
    found = var_assign_log_lines_from(offset).select { |l| l.include?("#<#{klass}: #{message}>") }
    t.assert_equal 1, found.size
    t.assert_include found[0].to_s, ' [error] '
  end
end

t.assert('Nginx::Var - a script rescues the exception of an assignment, whose message names the variable', 'GET /<call>/<name>/rescue on 18107') do
  [
    ['/setter/Var_Assign_No_Such/rescue', 'NameError', VAR_ASSIGN_NO_SUCH % 'Var_Assign_No_Such'],
    ['/set/var_assign_no_such/rescue', 'NameError', VAR_ASSIGN_NO_SUCH % 'var_assign_no_such'],
    ['/setter/uri/rescue', 'RuntimeError', VAR_ASSIGN_NOT_CHANGEABLE % 'uri'],
    ['/set/URI/rescue', 'RuntimeError', VAR_ASSIGN_NOT_CHANGEABLE % 'URI'],
    ['/setter/var_assign_mapped/rescue', 'RuntimeError', VAR_ASSIGN_NO_VALUE % 'var_assign_mapped'],
  ].each do |path, klass, message|
    res = var_assign(path)
    t.assert_equal 200, res.code, path
    t.assert_equal "raised: #{klass}: #{message}", res['body'], path
  end
end

t.assert('Nginx::Var - a log handler that assigns a variable that nginx does not know logs NameError', 'GET /log/no_such on 18107') do
  offset = File.size(var_assign_log_path)
  res = var_assign('/log/no_such')
  t.assert_equal 200, res.code
  t.assert_equal 'sent', res['body']
  message = VAR_ASSIGN_NO_SUCH % 'var_assign_no_such_in_log'
  found = []
  # nginx runs the log phase after the response is sent
  20.times do
    found = var_assign_log_lines_from(offset).select { |l| l.include?("#<NameError: #{message}>") }
    break unless found.empty?
    sleep 0.1
  end
  t.assert_equal 1, found.size
end

# The setter, set and mruby_set give a variable the same value: a variable
# of "set", the same with its name in uppercase, a variable with a
# set_handler ($args) and a variable of mruby_variable.
t.assert('Nginx::Var - the setter and set assign the same value to each kind of variable', 'GET /setter/<name> and /set/<name> on 18107') do
  %w[var_assign_plain VAR_ASSIGN_PLAIN args var_assign_declared].each do |name|
    %w[setter set].each do |call|
      res = var_assign("/#{call}/#{name}")
      t.assert_equal 200, res.code, "#{call} #{name}"
      t.assert_equal 'returned="42" read="42"', res['body'], "#{call} #{name}"
    end
  end
end

t.assert('Nginx::Var - mruby_set assigns the value that the setter and set assign, with and without a wait', 'GET /mruby_set/plain and /mruby_set_sleep/plain on 18107') do
  %w[/mruby_set/plain /mruby_set_sleep/plain].each do |path|
    res = var_assign(path)
    t.assert_equal 200, res.code, path
    t.assert_equal 'read="42"', res['body'], path
  end
end

t.report
