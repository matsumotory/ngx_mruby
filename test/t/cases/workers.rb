# nginx with a master process and several worker processes, and a reload.
# test/t/cases/_workers.rb starts that nginx, sends the requests and prints
# what it saw; this file checks it. Config: test/conf/workers/isolation.conf
# (port 18180, four workers), test/conf/workers/reload.conf (ports 18181
# and 12379, two workers) and test/conf/workers/shutdown.conf (ports 18185
# and 12393, one worker). workers_nginx is in test/t/cases/_prelude.rb.

t = SimpleTest.new "ngx_mruby test: several worker processes and a reload"

def workers_first(r, key)
  (r[key] || [])[0]
end

# "pid=1 set=2 rewrite=2" => {"pid" => "1", "set" => "2", "rewrite" => "2"}
def workers_fields(body)
  fields = {}
  body.to_s.split(" ").each do |pair|
    k, v = pair.split("=", 2)
    fields[k] = v
  end
  fields
end

# What is left in the stop, the error log, the sanitizer and valgrind
# reports of a run. A sanitizer report or a leak goes to the files that
# _workers.rb names; print the error log when the check fails.
def workers_check_exit(t, r, mode, workers)
  t.assert_nil workers_first(r, 'error')
  t.assert_equal "master exited 0; #{workers} of #{workers} workers ended", workers_first(r, 'exit')
  if workers_first(r, 'sanitizer') || workers_first(r, 'error_lines') != '0'
    puts File.read(File.join(ENV['NGINX_INSTALL_DIR'], 'logs', "workers_#{mode}.error.log"))
  end
  t.assert_equal '0', workers_first(r, 'error_lines')
  t.assert_nil workers_first(r, 'error_line')
  t.assert_nil workers_first(r, 'sanitizer')
  (r['valgrind'] || []).each do |summary|
    t.assert_equal '0', summary.split(':', 2)[1]
  end
end

iso = workers_nginx('isolation')

t.assert('workers - every worker of four answers from an mrb_state of its own, which its requests share', '18180 /worker') do
  t.assert_nil workers_first(iso, 'error')
  workers = workers_first(iso, 'workers').to_s.split(',')
  t.assert_equal 4, workers.size
  t.assert_equal workers_first(iso, 'master'), workers_first(iso, 'pid_file')
  t.assert_false workers.include?(workers_first(iso, 'master'))

  responses = iso['response'] || []
  t.assert_equal responses.size.to_s, workers_first(iso, 'requests')
  answered = {}
  responses.each do |response|
    status, body = response.split('|', 2)
    t.assert_equal '200', status
    f = workers_fields(body)
    t.assert_true workers.include?(f['pid'])
    # Each handler of the request ran once more in the state of this
    # worker: the counts of the worker go 1, 2, 3, ... and are the same for
    # the set, rewrite, access and content handlers.
    answered[f['pid']] = (answered[f['pid']] || 0) + 1
    t.assert_equal answered[f['pid']].to_s, f['content']
    t.assert_equal f['content'], f['set']
    t.assert_equal f['content'], f['rewrite']
    t.assert_equal f['content'], f['access']
    t.assert_equal '380', f['work']
  end
  # The connections reached every worker, each at least twice.
  t.assert_equal workers.sort, answered.keys.sort
  answered.each_value { |n| t.assert_true n >= 2 }
end

t.assert('workers - nginx with four workers stops with the master and every worker, without an error or a leak') do
  workers_check_exit(t, iso, 'isolation', 4)
end

rel = workers_nginx('reload')

t.assert('workers - a reload brings the new configuration and script, while the old workers finish the sleeps in flight', '18181, 12379') do
  t.assert_nil workers_first(rel, 'error')
  old = workers_first(rel, 'workers').to_s.split(',')
  t.assert_equal 2, old.size
  t.assert_equal workers_first(rel, 'master'), workers_first(rel, 'pid_file')

  # Before the reload: generation 1 answers from an old worker.
  status, body = workers_first(rel, 'before').to_s.split('|', 2)
  t.assert_equal '200', status
  t.assert_equal 'generation 1', body.to_s.split(' pid=')[0]
  t.assert_true old.include?(body.to_s.split(' pid=')[1])
  status, body = workers_first(rel, 'script_before').to_s.split('|', 2)
  t.assert_equal '200', status
  t.assert_equal 'script generation 1', body.to_s.split(' pid=')[0]
  t.assert_true old.include?(body.to_s.split(' pid=')[1])

  # After the SIGHUP: the new configuration answers from a new worker, and
  # once the old workers shut down, the new script as well.
  status, body = workers_first(rel, 'after').to_s.split('|', 2)
  t.assert_equal '200', status
  t.assert_equal 'generation 2', body.to_s.split(' pid=')[0]
  t.assert_false old.include?(body.to_s.split(' pid=')[1])
  status, body = workers_first(rel, 'script_after').to_s.split('|', 2)
  t.assert_equal '200', status
  t.assert_equal 'script generation 2', body.to_s.split(' pid=')[0]
  t.assert_false old.include?(body.to_s.split(' pid=')[1])

  # Every old worker was shutting down, and both sleeps were still in
  # flight in them.
  http_worker = workers_first(rel, 'http_sleep_worker')
  stream_worker = workers_first(rel, 'stream_sleep_worker')
  t.assert_true old.include?(http_worker)
  t.assert_true old.include?(stream_worker)
  t.assert_equal 'http,stream', workers_first(rel, 'in_flight')
  # The workers with a sleep in flight still ran; an old worker without one
  # may have ended already.
  alive = workers_first(rel, 'old_alive').to_s.split(',')
  t.assert_true alive.include?(http_worker)
  t.assert_true alive.include?(stream_worker)

  # The old workers answered with the configuration of generation 1 after
  # they had begun to shut down, and then ended.
  t.assert_equal "200|generation 1 pid=#{http_worker} released=true", workers_first(rel, 'http_in_flight')
  t.assert_equal 'stream generation 1', workers_first(rel, 'stream_in_flight')
  t.assert_equal 'shutdown,resumed', workers_first(rel, 'http_order')
  t.assert_equal 'shutdown,resumed', workers_first(rel, 'stream_order')
  t.assert_equal '2 of 2', workers_first(rel, 'old_ended')

  # Generation 2 answers on both protocols from its own two workers.
  new_workers = workers_first(rel, 'new_workers').to_s.split(',')
  t.assert_equal 2, new_workers.size
  new_workers.each { |w| t.assert_false old.include?(w) }
  status, body = workers_first(rel, 'after_release').to_s.split('|', 2)
  t.assert_equal '200', status
  t.assert_equal 'generation 2', body.to_s.split(' pid=')[0]
  t.assert_true new_workers.include?(body.to_s.split(' pid=')[1])
  t.assert_equal 'stream generation 2', workers_first(rel, 'stream_after')
end

t.assert('workers - nginx stops after the reload with the master and the workers of both generations, without an error or a leak') do
  workers_check_exit(t, rel, 'reload', 4)
end

down = workers_nginx('shutdown')

t.assert('workers - a stream session that sleeps when worker_shutdown_timeout expires ends then, and its code runs once', '12393') do
  t.assert_nil workers_first(down, 'error')
  # The old worker ended after the timeout of 1 second, not after the 10
  # seconds of the sleep.
  t.assert_true workers_first(down, 'shutdown_seconds').to_f < 5.0,
                "the old worker ended #{workers_first(down, 'shutdown_seconds')} seconds after the reload"
  # The session ended without the return of the location, and the code
  # neither started again nor resumed.
  t.assert_equal '', workers_first(down, 'shutdown_session')
  t.assert_equal '1', workers_first(down, 'shutdown_started')
  t.assert_equal '0', workers_first(down, 'shutdown_resumed')
end

t.assert('workers - nginx stops after the shutdown timeout with the master and the workers of both generations, without an error or a leak') do
  workers_check_exit(t, down, 'shutdown', 2)
end

t.report
