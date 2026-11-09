t = SimpleTest.new "ngx_mruby test: ENV and Process of the core gems mruby-env and mruby-process (test/conf/conf.d/62-gem-env-process.conf)"

GEM_ENV_PROCESS_PORT = 18118

def gem_env_process_lines(t)
  res = HttpRequest.new.get base(GEM_ENV_PROCESS_PORT) + '/gem_env_process'
  t.assert_equal 200, res.code
  res["body"].split("\n")
end

t.assert('mruby-env, mruby-process', 'ENV, Process, Signal and Kernel#sleep from a handler') do
  lines = gem_env_process_lines(t)
  t.assert_equal [
    "v",               # ENV#[]= and ENV#[]
    "v",               # ENV.to_h (iij/mruby-env had to_hash only)
    "1",               # ENV.select: ENV is Enumerable
    "v",               # ENV.delete returns the value
    "false",           # ENV.key? after the delete
    "NoMethodError",   # ENV.to_hash is gone
    "ArgumentError",   # a name with "=" (RuntimeError with iij/mruby-env)
    "true",            # Process.pid and $$
    "Float",           # Process.clock_gettime
    "false",           # no Process.fork
    "false",           # no Kernel#fork
    "false",           # no Kernel#system
    "true",            # Signal, which mruby-process depends on
    "1",               # Kernel#sleep is mruby-sleep's, which takes one argument
    "ArgumentError",   # sleep without an argument (iij/mruby-process slept forever)
    "true",            # Kernel#usleep of mruby-sleep
    "false,false",     # no Vedis (mruby-vedis) and no Cache (mruby-localmemcache)
  ], lines[0..-2]
end

t.assert('mruby-exit', 'Kernel#exit in a handler raises SystemExit: 500, and nginx keeps running') do
  pid = gem_env_process_lines(t).last

  res = HttpRequest.new.get base(GEM_ENV_PROCESS_PORT) + '/gem_env_process/exit'
  t.assert_equal 500, res.code

  # The test nginx runs a single process: the same process answers again.
  t.assert_equal pid, gem_env_process_lines(t).last
end

t.report
