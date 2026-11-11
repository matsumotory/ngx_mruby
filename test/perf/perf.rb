# frozen_string_literal: true

# Performance comparison driver for ngx_mruby (CRuby 3.0 or later, Linux,
# valgrind with callgrind and callgrind_control).
#
#   ruby test/perf/perf.rb BUILD_DIR             # measure one build
#   ruby test/perf/perf.rb BASE_DIR HEAD_DIR     # measure two builds and compare
#
# A BUILD_DIR is a build of test/build_release.sh (test/perf/run.sh and
# test/perf/compare.sh make them). For each scenario, and for each build in
# turn, perf.rb starts nginx with the soak test's configuration
# (a template in test/soak/, with master_process off) under
# `valgrind --tool=callgrind --instr-atstart=no`, checks one response, sends
# PERF_WARMUP requests or TCP sessions, switches instrumentation on with
# callgrind_control, sends PERF_N requests or sessions, dumps the profile
# with callgrind_control, and stops nginx. The dump holds the cost of the
# PERF_N measured units; Ir per request (per TCP session) is its Ir divided by
# PERF_N. The judged number leaves out the calls into mrb_incremental_gc
# and mrb_full_gc (the GC) and into mrb_vm_const_get (the misses of mruby's
# constant cache; see CONST_LOOKUP_FUNCTIONS). A window with 0 Ir, or without the expected number of
# calls of the scenario's request function (ngx_mrb_start_fiber for the
# HTTP scenarios; ngx_stream_mrb_start_fiber for stream_sleep; see
# REQUEST_FUNCTIONS and request_functions), fails the measurement.
#
# The agent proxy scenarios (proxy_*, responses_stream_plain_*, auth,
# route_json_*, ruby_call_*) use the template test/soak/nginx.agent.conf,
# and those with an upstream also get the mock LLM test/soak/mock_llm.rb on
# port base + 2, started before nginx and stopped after it.
#
# Why master_process off: callgrind_control reaches a process through
# valgrind's gdbserver (vgdb), and vgdb does not serve a process that valgrind
# forked, such as an nginx worker. With master_process off, the one nginx
# process runs the event loop and the request handlers as a worker does.
#
# With two builds, the change of head against base is judged per scenario on
# the judged number: WARN from PERF_WARN_PERCENT, FAIL from
# PERF_FAIL_PERCENT. A line of test/perf/accepted.txt whose condition the
# comparison matches (see accepted_for: the mruby version of both builds, or
# the pull request that PERF_PULL_REQUEST and PERF_BASE_REF name) shows a
# WARN or FAIL within its allowance as "ok (accepted: ...)". The exit status
# is 1 when a scenario is FAIL, when a
# measurement fails (in the base, an unexpected response is not an error when
# its only other problems are ngx_mruby's "mrb_run failed" lines: the
# scenario is shown as n/a; see summarize), or when no scenario was compared.
#
# See docs/test/README.md, "Performance comparison with callgrind".

require 'fileutils'
require 'json'
require 'socket'
require 'tmpdir'
require 'yaml'
require_relative '../soak/http_client'
require_relative '../soak/tcp_client'
require_relative '../soak/scenarios'

def env_int(name, default)
  value = ENV[name]
  return default if value.nil? || value.empty?

  Integer(value, 10)
end

def env_float(name, default)
  value = ENV[name]
  return default if value.nil? || value.empty?

  Float(value)
end

ROOT = File.expand_path('../..', __dir__)
CONF_TEMPLATE_DIR = File.join(ROOT, 'test/soak')
HANDLERS_DIR = File.join(ROOT, 'test/soak/handlers')
REPORT_DIR = ENV.fetch('PERF_REPORT_DIR', File.join(ROOT, 'build_perf'))

PORT = env_int('PERF_PORT_BASE', 12_370)
BACKEND_PORT = PORT + 1
MOCK_PORT = PORT + 2
N = env_int('PERF_N', 20_000)
WARMUP = env_int('PERF_WARMUP', 2000)
WARN_PERCENT = env_float('PERF_WARN_PERCENT', 3.0)
FAIL_PERCENT = env_float('PERF_FAIL_PERCENT', 5.0)

# The scenarios measured when PERF_SCENARIOS is not set: HTTP keep-alive
# and TCP scenarios of test/soak/scenarios.rb. proxy_stream_plain_1000,
# responses_stream_plain_1000 and route_json_64k are left out for their time
# (see docs/test/README.md); PERF_SCENARIOS names them.
DEFAULT_SCENARIOS = %w[hello headers var filter sleep sub_request file
                       proxy_plain_2k proxy_plain_64k proxy_stream_plain_50 responses_stream_plain_50 auth
                       route_json_2k ruby_call_1 ruby_call_10 stream_sleep].freeze

# The GC: the inclusive cost of the calls into the two entry points of
# mruby's collector, made from outside the collector. See parse_profile.
GC_ENTRIES = %w[mrb_incremental_gc mrb_full_gc].freeze
# The functions of mruby/src/gc.c that are not part of the collector and
# call an entry point: the allocator (mrb_obj_alloc runs an incremental GC
# step; the malloc wrappers run a full GC when an allocation fails), GC.start,
# mrb_garbage_collect and ObjectSpace.each_object.
GC_ALLOCATORS = %w[mrb_obj_alloc mrb_malloc mrb_malloc_simple mrb_calloc mrb_realloc mrb_realloc_simple
                   mrb_alloca gc_start mrb_garbage_collect mrb_objspace_each_objects].freeze
GC_SOURCE = 'mruby/src/gc.c'

# The constant lookups that miss mruby's constant cache: OP_GETCONST of
# mruby/src/vm.c calls mrb_vm_const_get only when the entry of the cache for
# its irep and symbol holds another constant. The cache has
# MRB_CONST_CACHE_SIZE (64) entries, indexed by a hash of the address of the
# irep and the symbol, so two lookups that a request makes can share an
# entry and then miss on every request, and whether they share one depends
# on where the ireps were allocated. The same binary measured about 700 Ir
# more per TCP session of stream_sleep in one CI run than in another (#766):
# 2 misses per session. The number w/o GC/const leaves the cost of these
# lookups out, and their number per request is reported as const_misses
# (RECORDED_FUNCTIONS). The cost is the self cost of mrb_vm_const_get and
# the inclusive cost of its calls into CONST_LOOKUP_CALLEES, the search of
# the table of each class, which is all that it calls in the profiles of
# the CI runs. A call into any other function is not subtracted, and the
# report prints it (const_unlisted): in a profile of auth on aarch64,
# callgrind shows mrb_vm_const_get calling mrb_vm_exec'2 with most of the
# request below it, which the code does not do (the VM leaves functions
# through fibers and non-local exits, and callgrind's call graph does not
# follow them), and the Ruby code of a const_missing would be such a call
# as well. Not subtracting keeps such cost in the judged number, where an
# ERROR would stop the comparison before a tag, which runs on aarch64.
# mrb_vm_const_get allocates only when it calls const_missing; a GC that such
# an allocation runs would be left out twice.
CONST_LOOKUP_FUNCTIONS = %w[mrb_vm_const_get].freeze
CONST_LOOKUP_CALLEES = %w[iv_get].freeze

# The functions that clear the whole constant cache (mrb_const_cache_clear in
# mruby/src/variable.c, which mrb_const_set, mrb_const_remove and
# mrb_define_const_id call, and mrb_include_module and mrb_prepend_module in
# mruby/src/class.c call; Object#extend and OP_SETCONST reach it through
# them). After a clear, every lookup of the rest of the request misses once:
# that cost does not depend on the layout, it is the cost of the code that
# clears. They are reported as const_clears (calls into the list from a
# function that is not in it, so a clear counts also where gcc inlines
# mrb_const_cache_clear into a caller; callgrind recorded 2 per call of
# Module#const_set on aarch64), and a scenario whose head clears
# the cache more often than its base is judged on the number w/o GC, with
# the constant lookups counted.
CONST_CACHE_CLEARS = %w[mrb_const_cache_clear mrb_const_set mrb_const_remove mrb_define_const_id
                        mrb_define_const mrb_include_module mrb_prepend_module].freeze

# The function that the scenarios run a known number of times per request.
# The window must hold exactly PERF_N times that many calls of it. A window
# that is empty (callgrind_control prints "OK." even when vgdb did not reach
# the process, so the instrumentation may not have been switched on) or that
# holds other requests fails the measurement instead of giving a number.
#
# The scenarios of test/soak/nginx.conf count ngx_mrb_start_fiber:
# ngx_mrb_run, which runs the Ruby code of a handler or filter, starts one
# fiber for each run, and nothing else calls ngx_mrb_start_fiber. They do not
# count ngx_mrb_run, because callgrind does not record its calls the same
# way in every build: in the aarch64 build of next at 45c9e52 (2026-10-04),
# it recorded a second call of ngx_mrb_run per request, in six of the seven
# scenarios as a call from ngx_mrb_http_get_module_ctx.part.0 to
# ngx_mrb_run'2 (although ngx_mrb_http_get_module_ctx does not call
# ngx_mrb_run), which made their windows hold two calls per request. It
# recorded one call of ngx_mrb_start_fiber per request in all seven, as in
# the x86_64 builds of the CI runner.
#
# Names are compared after base_name, so a copy that GCC makes of the
# function (.part.0, .isra.0, .constprop.0, .cold after the name) counts as
# the function, and a call from one copy to another counts once. One perf.rb
# measures both builds, so a pull request that renames the function lists
# the old and the new name here (a call between two listed names counts
# once as well); PERF_REQUEST_FUNCTIONS (comma-separated) overrides the list.
# An inlined function leaves no call in the profile. ngx_mrb_start_fiber is
# defined in ngx_http_mruby_async.c and called from ngx_http_mruby_module.c,
# so GCC does not inline it; a change that lets the compiler inline it
# (static in the file of its single caller, or a build with LTO) would leave
# every window with 0 calls and has to list a function that keeps a real
# call.
REQUEST_FUNCTIONS = ENV.fetch('PERF_REQUEST_FUNCTIONS', 'ngx_mrb_start_fiber').split(',').map(&:strip).reject(&:empty?).freeze
# Calls of the request function per request, by scenario; 1 when not listed.
REQUEST_FUNCTION_CALLS = Hash.new(1).merge('ruby_call_10' => 10).freeze

# The request function of the scenarios with an upstream (a mock in
# test/soak/scenarios.rb). nginx calls ngx_http_log_request once for each
# request it ends (for a subrequest only with log_subrequest on), with or
# without Ruby, so the scenarios without Ruby have a count too, and all the
# scenarios with an upstream count the same function. The /status requests
# that wake nginx for callgrind_control (see control) end inside the window
# when they come after the instrumentation was switched on, so the window may
# hold up to that many calls more than PERF_N times the count.
LOG_REQUEST_FUNCTIONS = %w[ngx_http_log_request].freeze

# The request function of the ruby_call_* scenarios (mruby_set_code). Its
# handler reaches ngx_mrb_run through a tail call, which callgrind does not
# always record as a call of ngx_mrb_run: in an aarch64 build, one of the ten
# calls per request of ruby_call_10 showed as a call from the handler to
# ngx_mrb_start_fiber, and ruby_call_1 showed none. nginx calls the handler
# through a pointer, once for each mruby_set_code.
SET_CODE_FUNCTIONS = %w[ngx_http_mruby_set_inline_handler].freeze
SCENARIO_REQUEST_FUNCTIONS = { 'ruby_call_1' => SET_CODE_FUNCTIONS, 'ruby_call_10' => SET_CODE_FUNCTIONS,
                               'stream_sleep' => %w[ngx_stream_mrb_start_fiber] }.freeze

# Functions whose calls per request are reported but not checked:
# - ruby_calls: the Ruby runs. ngx_mrb_run starts a fiber for each run of
#   Ruby code, and nothing else calls ngx_mrb_start_fiber; callgrind records
#   these calls also where it misses one of ngx_mrb_run (SET_CODE_FUNCTIONS).
#   In the scenarios of test/soak/nginx.conf, the request function counts
#   the same calls (REQUEST_FUNCTIONS). For stream_sleep, this includes
#   ngx_stream_mrb_start_fiber, once per completed TCP session.
# - non_buffered_calls: the calls of
#   ngx_http_upstream_process_non_buffered_request, which relays an
#   unbuffered response. nginx calls it when the upstream connection is
#   readable and when the client connection is writable; one call reads
#   from the upstream until recv() would block, up to proxy_buffer_size at a
#   time, and writes what it read to the client. How many calls a response
#   takes depends on how much of it had arrived at each call, that is on
#   timing, and each call costs Ir (NON_BUFFERED_CALL_IR).
# - const_misses: the calls of CONST_LOOKUP_FUNCTIONS, the misses of mruby's
#   constant cache, whose cost the number w/o GC/const leaves out.
# - const_clears: the clears of the whole constant cache (CONST_CACHE_CLEARS).
RECORDED_FUNCTIONS = { ruby_calls: %w[ngx_mrb_start_fiber ngx_stream_mrb_start_fiber],
                       non_buffered_calls: %w[ngx_http_upstream_process_non_buffered_request],
                       const_misses: CONST_LOOKUP_FUNCTIONS,
                       const_clears: CONST_CACHE_CLEARS }.freeze

# About how many Ir per request one more non_buffered_calls costs. Measured
# on aarch64 with proxy_stream_plain_50 and the mock writing the stream in
# one write, one write per event, and one write per event 1 ms apart: see
# "Agent proxy scenarios in the comparison" in docs/test/README.md.
NON_BUFFERED_CALL_IR = 1000

def request_functions(scenario)
  SCENARIO_REQUEST_FUNCTIONS.fetch(scenario.name) { scenario.mock ? LOG_REQUEST_FUNCTIONS : REQUEST_FUNCTIONS }
end

# Where the request function of a scenario is set, for the message of a
# window that does not hold the expected calls.
def request_functions_source(scenario)
  if SCENARIO_REQUEST_FUNCTIONS.key?(scenario.name)
    'SCENARIO_REQUEST_FUNCTIONS in test/perf/perf.rb'
  elsif scenario.mock
    'LOG_REQUEST_FUNCTIONS in test/perf/perf.rb'
  else
    'REQUEST_FUNCTIONS in test/perf/perf.rb (PERF_REQUEST_FUNCTIONS overrides it)'
  end
end

# The name of a function without the suffixes that callgrind ('2: seen on the
# call stack already) and GCC (.part.0, .isra.0, .constprop.0, .cold,
# .lto_priv.0: a clone or a split part of the function) add to it.
def base_name(name)
  name.to_s.sub(/'\d+\z/, '').sub(/(?:\.(?:part|isra|constprop|cold|lto_priv)(?:\.\d+)?)+\z/, '')
end

# Seconds. Everything runs under valgrind, which is slow to start, and the
# first requests after the instrumentation is switched on are translated again.
START_TIMEOUT = 300
IO_TIMEOUT = 120
CONTROL_TIMEOUT = 120
STOP_TIMEOUT = 300
QUIET_TIMEOUT = 5
WAKE_INTERVAL = 0.2

# Lines of error.log (and nginx's stderr) that fail a measurement.
LOG_PATTERNS = ['[error]', '[alert]', '[crit]', '[emerg]'].freeze
# How many of those lines scan_logs reports per log. When a log has more, it
# reports one line more that says so (log_more_lines), which counts as a
# problem like any other line (see summarize).
LOG_LINES_KEPT = 5

def log_more_lines(log_name)
  "#{log_name}: more than #{LOG_LINES_KEPT} lines at the error level or above"
end

# The line that ngx_mruby logs at the error level when the Ruby code of a
# request raises (ngx_mrb_raise_error in src/http/ngx_http_mruby_core.c:
# "mrb_run failed: return 500 HTTP status code to client: error: ..."), as
# scan_logs reports it. A base that lacks a Ruby method or class that a
# scenario uses logs one with its unexpected response, so summarize does not
# count it against n/a.
MRB_RUN_FAILED_LINE = /\Aerror\.\S+\.log: \S+ \S+ \[error\] \d+#\d+: (?:\*\d+ )?mrb_run failed: /

class PerfError < StandardError; end

# A response that is not the one the scenario expects. In the base this is
# what a scenario that needs a feature of the head gets (with ngx_mruby's
# "mrb_run failed" line in error.log when the feature is a Ruby method or
# class); every other failure of a measurement is an error of the measurement.
class ResponseError < PerfError; end

def monotonic
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def log(line = '')
  puts line
  $stdout.flush
end

# A build of test/build_release.sh.
class Build
  attr_reader :label, :dir

  def initialize(label, dir)
    @label = label
    @dir = File.expand_path(dir)
  end

  def nginx_bin
    File.join(@dir, 'nginx/sbin/nginx')
  end

  def prefix
    File.join(@dir, 'nginx/perf')
  end

  # The configuration of a scenario: its template (test/soak/nginx.conf or
  # another one, see Scenario#conf) after the replacements.
  def conf_path(scenario)
    File.join(prefix, 'conf', scenario.conf)
  end

  def log_dir
    File.join(prefix, 'logs')
  end

  # The callgrind profiles of the measured windows, one per scenario.
  def out_dir
    File.join(@dir, 'callgrind')
  end

  def write_confs(scenarios)
    FileUtils.mkdir_p([File.join(prefix, 'conf'), log_dir, out_dir])
    scenarios.uniq(&:conf).each do |scenario|
      path = File.join(CONF_TEMPLATE_DIR, scenario.conf)
      template = File.read(path)
      conf = template.sub(/^master_process on;$/, 'master_process off;')
      raise PerfError, "#{path}: no line 'master_process on;' to replace" if conf == template

      conf = conf.gsub('__SOAK_PORT__', PORT.to_s)
                 .gsub('__SOAK_BACKEND_PORT__', BACKEND_PORT.to_s)
                 .gsub('__SOAK_MOCK_PORT__', MOCK_PORT.to_s)
                 .gsub('__SOAK_HANDLERS__', HANDLERS_DIR)
      File.write(conf_path(scenario), conf)
    end
  end
end

# nginx (one process, master_process off) running under callgrind for one
# scenario.
class NginxUnderCallgrind
  def initialize(build, scenario)
    @build = build
    @name = scenario.name
    @conf_path = build.conf_path(scenario)
    @profile_base = File.join(build.out_dir, "callgrind.out.#{@name}")
    @error_log = File.join(build.log_dir, 'error.log')
    @stderr_log = File.join(build.log_dir, 'stderr.log')
    @control_log = File.join(build.out_dir, "callgrind_control.#{@name}.log")
  end

  def start
    FileUtils.rm_f([@error_log, @stderr_log, @control_log, @profile_base] +
                   Dir.glob("#{@profile_base}.*") +
                   Dir.glob(File.join(@build.out_dir, "valgrind.#{@name}.*.log")))
    @pid = Process.spawn('valgrind', '--tool=callgrind', '--instr-atstart=no',
                         "--callgrind-out-file=#{@profile_base}.%p",
                         "--log-file=#{File.join(@build.out_dir, "valgrind.#{@name}.%p.log")}",
                         @build.nginx_bin, '-p', "#{@build.prefix}/", '-c', @conf_path,
                         %i[out err] => [@stderr_log, 'w'])
    deadline = monotonic + START_TIMEOUT
    loop do
      raise PerfError, "nginx exited at startup:\n#{File.read(@stderr_log)}" if exited?
      return if listening?
      raise PerfError, "nginx not listening on #{PORT} after #{START_TIMEOUT} s" if monotonic > deadline

      sleep 0.1
    end
  end

  # Runs callgrind_control with args for nginx. callgrind_control talks to
  # valgrind's gdbserver through vgdb. When vgdb cannot interrupt a process
  # that waits in epoll_wait (no ptrace), the command runs the next time the
  # process runs code, so a small request (stub_status at /status) is sent
  # every WAKE_INTERVAL until callgrind_control returns. Returns the number of
  # those requests. callgrind_control exits with 0 also when it did not find
  # the process, so its output must say "OK.".
  def control(*args)
    output = "#{@control_log}.last"
    pid = Process.spawn('callgrind_control', *args, @pid.to_s, %i[out err] => [output, 'w'])
    deadline = monotonic + CONTROL_TIMEOUT
    next_wake = monotonic + WAKE_INTERVAL
    wakes = 0
    loop do
      done, status = Process.waitpid2(pid, Process::WNOHANG)
      if done
        text = File.read(output)
        File.open(@control_log, 'a') { |f| f.write(text) }
        File.delete(output)
        unless status.success? && text.match?(/^\s*OK\.$/) && !text.include?('Error')
          raise PerfError, "callgrind_control #{args.join(' ')} failed (#{status.inspect}): #{text.strip}"
        end

        return wakes
      end
      if monotonic > deadline
        Process.kill(:KILL, pid)
        Process.wait(pid)
        raise PerfError, "callgrind_control #{args.join(' ')} did not return within #{CONTROL_TIMEOUT} s; see #{@control_log}"
      end
      if monotonic >= next_wake
        code, = get_closed('/status')
        raise PerfError, "/status returned #{code}" unless code == 200

        wakes += 1
        next_wake = monotonic + WAKE_INTERVAL
      end
      sleep 0.01
    end
  end

  # The profile that the dump of callgrind_control wrote: valgrind adds the
  # number of the dump to the file name. The profile at exit goes to the file
  # name without a number.
  def dump_file
    file = "#{@profile_base}.#{@pid}.1"
    raise PerfError, "callgrind_control --dump wrote no #{file}" unless File.exist?(file)

    file
  end

  # Stops nginx with SIGQUIT, keeps the dump as callgrind.out.<scenario> and
  # removes the profiles written at exit. Returns a list of problems.
  def stop(dump)
    return [] unless @pid

    problems = []
    begin
      Process.kill(:QUIT, @pid)
    rescue Errno::ESRCH
      nil
    end
    deadline = monotonic + STOP_TIMEOUT
    next_poke = monotonic + WAKE_INTERVAL
    until exited? || monotonic > deadline
      if monotonic >= next_poke
        poke
        next_poke = monotonic + WAKE_INTERVAL
      end
      sleep 0.1
    end
    unless exited?
      problems << "nginx did not exit within #{STOP_TIMEOUT} s of SIGQUIT; killed"
      begin
        Process.kill(:KILL, @pid)
      rescue Errno::ESRCH
        nil
      end
      Process.wait(@pid)
    end
    problems << "nginx exited with #{@status.inspect}" if @status && !@status.success?
    @pid = nil
    File.rename(dump, @profile_base) if dump && File.exist?(dump)
    FileUtils.rm_f(Dir.glob("#{@profile_base}.*"))
    problems + scan_logs
  end

  private

  def exited?
    return true if @status

    pid, status = Process.waitpid2(@pid, Process::WNOHANG)
    @status = status if pid
    !pid.nil?
  end

  def listening?
    Socket.tcp('127.0.0.1', PORT, connect_timeout: 1).close
    true
  rescue SystemCallError
    false
  end

  # Under valgrind, SIGQUIT did not end nginx's wait in epoll_wait: nginx
  # logged the signal and shut down only at its next event, and with no
  # connection open (a base that failed its first response) it was killed
  # after STOP_TIMEOUT. A connection is such an event; it comes after the
  # dump, so it is not in the window.
  def poke
    Socket.tcp('127.0.0.1', PORT, connect_timeout: 1).close
  rescue SystemCallError
    nil
  end

  # Keeps the logs as error.<scenario>.log and stderr.<scenario>.log and
  # returns the lines that match LOG_PATTERNS: up to LOG_LINES_KEPT of each
  # log, and after them a line saying that the log has more.
  def scan_logs
    problems = []
    [@error_log, @stderr_log].each do |path|
      next unless File.exist?(path)

      kept = path.sub(/\.log\z/, ".#{@name}.log")
      File.rename(path, kept)
      lines = 0
      File.foreach(kept) do |line|
        next unless LOG_PATTERNS.any? { |pattern| line.include?(pattern) }

        if lines == LOG_LINES_KEPT
          problems << log_more_lines(File.basename(kept))
          break
        end
        problems << "#{File.basename(kept)}: #{line.strip}"
        lines += 1
      end
    end
    problems
  end
end

def get_closed(path, headers = {})
  client = Client.new(PORT, io_timeout: IO_TIMEOUT)
  client.get(path, headers, close: true)
ensure
  client&.close
end

def check_response(scenario, status, headers, body)
  return if expected_response?(scenario, status, headers, body)

  raise ResponseError, "#{scenario.path}: unexpected response #{status} #{body[0, 200].inspect} #{headers.inspect}"
end

# Waits until stub_status shows that the only open connection is the one
# asking it, so that no work of the warmup is left when the instrumentation
# is switched on.
def wait_quiet
  deadline = monotonic + QUIET_TIMEOUT
  loop do
    code, _headers, body, = get_closed('/status')
    raise PerfError, "/status returned #{code}" unless code == 200
    return if body[/Active connections:\s*(\d+)/, 1] == '1'
    raise PerfError, "connections still open #{QUIET_TIMEOUT} s after the warmup: #{body.strip}" if monotonic > deadline

    sleep 0.01
  end
end

# Sends count HTTP requests over keep-alive (opening another connection
# after nginx reaches keepalive_requests), or count completed TCP sessions,
# one per connection. Every response is checked. HTTP returns its open
# client so closing it stays outside the window; TCP includes closure/EOF.
def scenario_requests(scenario, count)
  if scenario.mode == :tcp
    count.times { StreamClient.check(BACKEND_PORT, scenario.body, io_timeout: IO_TIMEOUT) }
    return nil
  end

  client = nil
  count.times do
    client ||= Client.new(PORT, io_timeout: IO_TIMEOUT)
    status, headers, body, keep_alive = scenario_request(client, scenario)
    check_response(scenario, status, headers, body)
    next if keep_alive

    client.close
    client = nil
  end
  client
end

# Reads a callgrind profile. Returns the total Ir, the Ir and number of the
# calls into the GC, the Ir of the constant lookups that missed the cache
# (const_ir: see CONST_LOOKUP_FUNCTIONS), the Ir of the other calls of
# mrb_vm_const_get by callee (const_unlisted), and the number of calls of
# the request function: calls
# into one of functions (REQUEST_FUNCTIONS by default; compared by
# base_name) from a function that is not one of them. With recorded (a Hash
# of name => functions), also returns recorded_calls, the number of calls of
# each of those lists counted the same way.
#
# Format: https://valgrind.org/docs/manual/cl-format.html. A cost line is
# "<positions> <events>"; the cost line after a calls= line is the inclusive
# cost of that call. Names may be compressed as "(id) name" on first use and
# "(id)" afterwards. fl= names the file of the functions that follow.
#
# Which calls are the GC: a call into mrb_incremental_gc or mrb_full_gc whose
# caller is outside the collector, that is, a function of another file or one
# of GC_ALLOCATORS, and where neither name has a recursion suffix ('2, '3,
# ...: callgrind saw the function on the call stack already). A full GC that
# mrb_incremental_gc runs is part of the cost of the outer call and is not
# counted again. Inside the collector, callgrind's call graph does not follow
# the machine code: in a build for aarch64 it shows final_marking_phase
# calling mrb_incremental_gc'2, which the code does not do. The outermost call
# of each GC returns to its caller, and its inclusive cost is the cost of the
# whole GC (it equals the inclusive cost that callgrind_annotate
# --inclusive=yes prints for mrb_incremental_gc without a suffix). The GC
# entry points do not call themselves, and the allocators do not run inside
# the collector, so a name with a recursion suffix is never an outermost
# call. GCC's suffixes are allowed: mrb_obj_alloc calling
# mrb_incremental_gc.part.0 is a GC, mrb_incremental_gc calling its own
# .part.0 is not (its caller is in the collector).
def parse_profile(path, functions = REQUEST_FUNCTIONS, recorded = {})
  names = { fn: {}, fl: {} }
  resolve = lambda do |table, spec|
    if (m = spec.match(/\A\((\d+)\)(?: (.*))?\z/))
      names[table][m[1]] = m[2] if m[2]
      names[table].fetch(m[1])
    else
      spec
    end
  end
  no_recursion = ->(name) { !name.to_s.include?("'") }
  outside_collector = lambda do |name, file|
    no_recursion.call(name) && (GC_ALLOCATORS.include?(base_name(name)) || !file.to_s.end_with?(GC_SOURCE))
  end
  positions = 1
  ir_index = 0
  totals = nil
  self_ir = 0
  gc_ir = 0
  gc_calls = 0
  const_ir = 0
  const_unlisted = Hash.new(0)
  request_calls = 0
  recorded_calls = recorded.transform_values { 0 }
  file = fn = fn_file = cfn = nil
  call_count = nil
  File.foreach(path, chomp: true) do |line|
    case line
    when /\A[0-9+\-*]/
      ir = line.split[positions + ir_index].to_i
      if call_count
        if GC_ENTRIES.include?(base_name(cfn)) && no_recursion.call(cfn) && outside_collector.call(fn, fn_file)
          gc_ir += ir
          gc_calls += call_count
        end
        if CONST_LOOKUP_FUNCTIONS.include?(base_name(fn)) && !CONST_LOOKUP_FUNCTIONS.include?(base_name(cfn))
          if CONST_LOOKUP_CALLEES.include?(base_name(cfn))
            const_ir += ir
          else
            const_unlisted[cfn] += ir
          end
        end
        request_calls += call_count if functions.include?(base_name(cfn)) && !functions.include?(base_name(fn))
        recorded.each do |key, list|
          recorded_calls[key] += call_count if list.include?(base_name(cfn)) && !list.include?(base_name(fn))
        end
        call_count = nil
      else
        self_ir += ir
        const_ir += ir if CONST_LOOKUP_FUNCTIONS.include?(base_name(fn))
      end
    when /\Afl=(.*)\z/ then file = resolve.call(:fl, Regexp.last_match(1))
    when /\A(?:fi|fe|cfi|cfl)=(.*)\z/ then resolve.call(:fl, Regexp.last_match(1))
    when /\Afn=(.*)\z/
      fn = resolve.call(:fn, Regexp.last_match(1))
      fn_file = file
    when /\Acfn=(.*)\z/ then cfn = resolve.call(:fn, Regexp.last_match(1))
    when /\Acalls=(\d+)/ then call_count = Regexp.last_match(1).to_i
    when /\Apositions:\s*(.*)\z/ then positions = Regexp.last_match(1).split.size
    when /\Aevents:\s*(.*)\z/ then ir_index = Regexp.last_match(1).split.index('Ir') or raise PerfError, "#{path}: no Ir event"
    when /\A(?:totals|summary):\s*(.*)\z/ then totals = Regexp.last_match(1).split[ir_index].to_i
    end
  end
  raise PerfError, "#{path}: no totals line" unless totals
  raise PerfError, "#{path}: totals #{totals} differ from the sum of the costs #{self_ir}" unless totals == self_ir

  result = { ir: totals, gc_ir: gc_ir, gc_calls: gc_calls, const_ir: const_ir, const_unlisted: const_unlisted.to_h,
             request_calls: request_calls }
  result[:recorded_calls] = recorded_calls unless recorded.empty?
  result
end

# The Ir of a profile without the GC and without the constant lookups that
# missed the cache (CONST_LOOKUP_FUNCTIONS): w/o GC/const.
def noconst_ir(profile)
  profile[:ir] - profile[:gc_ir] - profile[:const_ir]
end

# Fails the measurement unless the window holds the PERF_N requests of the
# scenario: Ir above 0 and PERF_N times REQUEST_FUNCTION_CALLS calls of the
# request function (for LOG_REQUEST_FUNCTIONS, up to wakes more).
def check_window(scenario, dump, profile, wakes)
  raise PerfError, "#{dump}: the window is empty (0 Ir); the instrumentation was not switched on" if profile[:ir].zero?

  functions = request_functions(scenario)
  per_request = REQUEST_FUNCTION_CALLS[scenario.name]
  expected = N * per_request
  extra = functions.equal?(LOG_REQUEST_FUNCTIONS) ? wakes : 0
  return if profile[:request_calls].between?(expected, expected + extra)

  range = extra.zero? ? expected.to_s : "#{expected} to #{expected + extra} (#{wakes} wake requests)"
  raise PerfError, "#{dump}: #{profile[:request_calls]} calls of #{functions.join('/')} in the window, " \
                   "expected #{range} (#{per_request} per request, PERF_N=#{N}); " \
                   "if the function was renamed, see #{request_functions_source(scenario)}"
end

# A check of base_name and parse_profile on a made-up profile, run with
# `ruby test/perf/perf.rb --self-test` (compare.sh and run.sh run it first).
# It needs no build and no valgrind. Returns the list of failures.
SELF_TEST_PROFILE = <<~PROFILE
  version: 1
  positions: line
  events: Ir
  summary: 121

  fl=(1) /b/tree/src/http/ngx_http_mruby_module.c
  fn=(1) ngx_http_mruby_content_handler
  1 10
  cfn=(2) ngx_mrb_run.isra.0
  calls=3 2
  1 30
  cfn=(3) ngx_mrb_run_fiber
  calls=2 3
  1 4
  fn=(2)
  2 10
  cfn=(4) ngx_mrb_run.part.0
  calls=3 4
  2 15
  fn=(4)
  4 10
  cfn=(5) ngx_mrb_run.cold
  calls=1 5
  4 5
  fn=(5)
  5 5
  fn=(3)
  3 4
  fn=(6) ngx_http_mruby_rewrite_handler
  6 1
  cfn=(7) ngx_mrb_run'2
  calls=1 7
  6 0
  fl=(2) /b/tree/mruby/src/gc.c
  fn=(8) mrb_obj_alloc
  8 5
  cfn=(9) mrb_incremental_gc.part.0
  calls=2 9
  8 40
  fn=(9)
  9 30
  cfn=(10) mrb_full_gc
  calls=1 10
  9 10
  fn=(10)
  10 10
  fn=(11) final_marking_phase
  11 1
  cfn=(12) mrb_incremental_gc'2
  calls=1 12
  11 0
  fl=(3) /b/tree/mruby/src/vm.c
  fn=(13) mrb_vm_exec
  13 3
  cfn=(14) mrb_vm_const_get
  calls=2 14
  13 32
  fl=(4) /b/tree/mruby/src/variable.c
  fn=(14)
  14 7
  cfn=(15) iv_get.constprop.1
  calls=2 15
  14 5
  cfn=(14)
  calls=1 14
  14 3
  cfn=(16) mrb_vm_exec'2
  calls=1 16
  14 20
  fn=(15)
  15 5
  fl=(3)
  fn=(16)
  16 20

  totals: 121
PROFILE

def self_test
  failures = []
  {
    'ngx_mrb_run' => 'ngx_mrb_run', 'ngx_mrb_run.part.0' => 'ngx_mrb_run', "ngx_mrb_run.isra.0'2" => 'ngx_mrb_run',
    'ngx_mrb_run.constprop.0.isra.0' => 'ngx_mrb_run', 'ngx_mrb_run.cold' => 'ngx_mrb_run',
    'ngx_mrb_run.lto_priv.0' => 'ngx_mrb_run', 'ngx_mrb_run_fiber' => 'ngx_mrb_run_fiber',
    'gc_mark_children.constprop.0' => 'gc_mark_children', "mrb_vm_exec'3" => 'mrb_vm_exec'
  }.each do |name, expected|
    failures << "base_name(#{name.inspect}) is #{base_name(name).inspect}, expected #{expected.inspect}" unless base_name(name) == expected
  end
  path = File.join(Dir.tmpdir, "perf-self-test-#{Process.pid}.out")
  File.write(path, SELF_TEST_PROFILE)
  begin
    # The handler calls the .isra.0 clone 3 times (counted); the clone calls
    # .part.0 and .cold (copies of the same function, not counted); another
    # handler calls ngx_mrb_run'2 once (counted); ngx_mrb_run_fiber is
    # another function. mrb_obj_alloc calls mrb_incremental_gc.part.0 twice
    # (40 Ir, the GC); the full GC inside it and final_marking_phase calling
    # mrb_incremental_gc'2 are not counted again. mrb_vm_exec calls
    # mrb_vm_const_get twice: the constant lookups are its self cost and its
    # calls of iv_get (12 Ir); its call of itself is not counted again, and
    # the call of mrb_vm_exec'2 that callgrind can show below it is not
    # subtracted but reported (const_unlisted).
    # The list is given, not taken from REQUEST_FUNCTIONS, so that the
    # self-test does not depend on PERF_REQUEST_FUNCTIONS.
    expected = { ir: 121, gc_ir: 40, gc_calls: 2, const_ir: 12, const_unlisted: { "mrb_vm_exec'2" => 20 }, request_calls: 4 }
    got = parse_profile(path, %w[ngx_mrb_run])
    failures << "parse_profile returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
    failures << "judged_ir gave #{noconst_ir(got)}, expected 69" unless noconst_ir(got) == 69
    # Another request function, and recorded functions: the handler calls
    # ngx_mrb_run_fiber twice; nothing calls ngx_http_log_request.
    expected = expected.merge(request_calls: 2, recorded_calls: { ruby_calls: 4, log: 0 })
    got = parse_profile(path, %w[ngx_mrb_run_fiber], { ruby_calls: %w[ngx_mrb_run], log: %w[ngx_http_log_request] })
    failures << "parse_profile with other functions returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
    # A stream start has the same clone/recursion accounting, but does not
    # count the HTTP control requests that wake callgrind.
    File.write(path, SELF_TEST_PROFILE.gsub('ngx_mrb_run', 'ngx_stream_mrb_start_fiber'))
    got = parse_profile(path, %w[ngx_stream_mrb_start_fiber], { ruby_calls: %w[ngx_stream_mrb_start_fiber], log: %w[ngx_http_log_request] })
    expected = { ir: 121, gc_ir: 40, gc_calls: 2, const_ir: 12, const_unlisted: { "mrb_vm_exec'2" => 20 }, request_calls: 4, recorded_calls: { ruby_calls: 4, log: 0 } }
    failures << "stream profile returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
  ensure
    File.delete(path)
  end
  failures + self_test_summary
end

# The checks of self_test on the comparison of made-up results: when a base
# is n/a and when it is an ERROR, the note on non_buffered_calls, and the
# list that the window message names.
def self_test_summary
  failures = []
  builds = [Struct.new(:label).new('base'), Struct.new(:label).new('head')]
  scenario = Scenario.new(name: 'made_up', mock: [])
  ok = { problems: [], ir_per_request: 50_000.0, nogc_per_request: 50_000.0, noconst_per_request: 50_000.0, gc_ir: 0, ir: 1,
         recorded_per_request: { ruby_calls: 0.0, non_buffered_calls: 5.0 } }
  unexpected = 'ResponseError: /v1/plain: unexpected response 502'
  connect = 'error.made_up.log: [error] connect() failed (111: Connection refused) while connecting to upstream'
  # What ngx_mrb_raise_error logs when the base lacks a method that the
  # scenario calls (the form of a line from a real run).
  mrb_run_failed = 'error.made_up.log: 2026/10/03 22:59:25 [error] 7#0: *2 mrb_run failed: return 500 HTTP status code ' \
                   "to client: error: undefined method 'made_up' (NoMethodError), client: 127.0.0.1, server: , " \
                   'request: "POST /v1/plain HTTP/1.1", host: "localhost"'
  # Lines that MRB_RUN_FAILED_LINE must not match, so they stay ERROR: what
  # ngx_mrb_raise_cycle_error logs (an error outside a request, such as
  # init_worker), and the request line of ngx_mrb_raise_error in nginx's
  # stderr instead of error.log.
  cycle_failed = "error.made_up.log: 2026/10/03 22:59:25 [error] 7#0: mrb_run failed. error: undefined method 'made_up' (NoMethodError)"
  stderr_failed = mrb_run_failed.sub('error.made_up.log: ', 'stderr.made_up.log: ')
  [
    ['n/a (base: unexpected response)', [unexpected]],
    ['ERROR', [unexpected, connect]],
    ['n/a (base: unexpected response)', [unexpected, mrb_run_failed]],
    ['ERROR', [unexpected, mrb_run_failed, connect]],
    ['ERROR', [unexpected, mrb_run_failed, log_more_lines('error.made_up.log')]],
    ['ERROR', [unexpected, cycle_failed]],
    ['ERROR', [unexpected, stderr_failed]]
  ].each do |expected, problems|
    base = { problems: problems, unexpected_response: true }
    _header, rows, = summarize(builds, [scenario], { %w[base made_up] => base, %w[head made_up] => ok })
    got = rows.first.last
    failures << "summarize with base problems #{problems.inspect} gave #{got.inspect}, expected #{expected.inspect}" unless got == expected
  end
  {
    5.0 => '', 5.08 => '+0.08 per request: about +80 Ir, +0.16% of base w/o GC/const)',
    6.6 => '+1.60 per request: about +1600 Ir, +3.20% of base w/o GC/const; the change of this scenario may come from when the response arrived)'
  }.each do |head_calls, expected|
    head = ok.merge(recorded_per_request: { ruby_calls: 0.0, non_buffered_calls: head_calls })
    got = non_buffered_effect([ok, head])
    failures << "non_buffered_effect with #{head_calls} calls gave #{got.inspect}, expected one ending #{expected.inspect}" unless got.end_with?(expected)
  end
  # The misses of the constant cache: stream_sleep of the two runs of #766
  # missed 2 lookups per session in one (about 700 Ir) and none in the other.
  base = ok.merge(recorded_per_request: { const_misses: 0.0 }, const_ir_per_request: 0.0)
  {
    [0.0, 0.0] => '', [0.001, 0.4] => '',
    [2.0, 698.0] => ' (const_misses +2.00 per request: +698 Ir, +1.40% of base w/o GC/const, not judged)',
    [2.0, 750.0] => ' (const_misses +2.00 per request: +750 Ir, +1.50% of base w/o GC/const, not judged; ' \
                    'more constant lookups of head miss the constant cache of mruby)',
    [-2.0, -750.0] => ' (const_misses -2.00 per request: -750 Ir, -1.50% of base w/o GC/const, not judged; ' \
                      'fewer constant lookups of head miss the constant cache of mruby)'
  }.each do |(calls, ir), expected|
    head = ok.merge(recorded_per_request: { const_misses: calls }, const_ir_per_request: ir)
    got = const_miss_effect([base, head])
    failures << "const_miss_effect with #{calls} calls and #{ir} Ir gave #{got.inspect}, expected #{expected.inspect}" unless got == expected
  end
# A head that clears the constant cache once more per request is judged
# w/o GC: 40 more misses (+14000 Ir, +28% w/o GC) are a FAIL there and
# nothing w/o GC/const; with the same clears it is judged w/o GC/const.
scenario = Scenario.new(name: 'made_up', mock: [])
base = ok.merge(recorded_per_request: { const_misses: 0.0, const_clears: 1.0 }, const_ir_per_request: 0.0)
[
  # head clears per request (base 1.0), head w/o GC, judged on, verdict, failed, end of the line
  [2.0, 64_000.0, 'w/o GC', 'FAIL', true, '; head clears the constant cache of mruby more often: judged w/o GC]'],
  [2.0, 51_800.0, 'w/o GC', 'WARN', false, ': judged w/o GC]'],
  [1.0, 64_000.0, 'w/o GC/const', 'ok', false, 'const lookups 0/14000 Ir]'],
  [0.0, 64_000.0, 'w/o GC/const', 'ok', false, 'const lookups 0/14000 Ir]']
].each do |clears, head_nogc, judged_on, verdict, expected_failed, line_end|
  head = ok.merge(nogc_per_request: head_nogc, noconst_per_request: 50_000.0, const_ir_per_request: 14_000.0,
                  recorded_per_request: { const_misses: 40.0, const_clears: clears })
  _header, rows, _notes, failed = summarize(builds, [scenario], { %w[base made_up] => base, %w[head made_up] => head })
  got = rows.first.values_at(-2, -1)
  line = const_cost_line([base, head])
  next if got == [judged_on, verdict] && failed == expected_failed && line.end_with?(line_end)

  failures << "clears #{clears} with head #{head_nogc} w/o GC gave #{got.inspect} (failed #{failed}), line #{line.inspect}; " \
              "expected #{[judged_on, verdict].inspect} (failed #{expected_failed}), a line ending #{line_end.inspect}"
end
# A call of mrb_vm_const_get into a function outside CONST_LOOKUP_CALLEES
# is printed, not subtracted.
a = ok.merge(const_ir_per_request: 300.0, const_unlisted_per_request: { "mrb_vm_exec'2" => 8000.0 })
b = ok.merge(const_ir_per_request: 300.0, const_unlisted_per_request: {})
expected = " [const lookups 300/300 Ir; not subtracted: mrb_vm_exec'2 8000/0 Ir]"
got = const_cost_line([a, b])
failures << "const_cost_line with an unlisted callee gave #{got.inspect}, expected #{expected.inspect}" unless got == expected
failures << "const_cost_line without lookups gave #{const_cost_line([ok, ok]).inspect}" unless const_cost_line([ok, ok]) == ''
  {
    'made_up' => 'LOG_REQUEST_FUNCTIONS', 'ruby_call_10' => 'SCENARIO_REQUEST_FUNCTIONS', 'hello' => 'PERF_REQUEST_FUNCTIONS'
  }.each do |name, list|
    s = Scenario.new(name: name, mock: name == 'made_up' ? [] : nil)
    begin
      check_window(s, 'dump', { ir: 1, request_calls: 0 }, 0)
      failures << "check_window accepted a window of #{name} without calls"
    rescue PerfError => e
      failures << "the window message of #{name} does not name #{list}: #{e.message}" unless e.message.include?(list)
    end
  end
  stream = Scenario.new(name: 'stream_sleep', mode: :tcp)
  unless request_functions(stream) == %w[ngx_stream_mrb_start_fiber]
    failures << 'stream_sleep must count stream fiber starts, not HTTP requests or wakes'
  end
  [0, N - 1, N + 1].each do |calls|
    begin
      check_window(stream, 'stream dump', { ir: 1, request_calls: calls }, 2)
      failures << "stream window accepted #{calls} calls instead of #{N}"
    rescue PerfError
      nil
    end
  end
  begin
    check_window(stream, 'stream dump', { ir: 1, request_calls: N }, 2)
  rescue PerfError => e
    failures << "stream window rejected exactly N sessions: #{e.message}"
  end
  failures + self_test_accepted(builds, ok)
end

# The checks of self_test on the accepted differences: the reading of
# test/perf/accepted.txt and of made-up lines, the mruby version, and the
# verdicts of made-up results of auth (the base without GC as on #678).
def self_test_accepted(builds, ok)
  failures = []
  begin
    load_accepted
  rescue PerfError => e
    failures << "load_accepted: #{e.message}"
  end
  names = %w[auth hello]
  text = "# comment\n\nmruby-version 4.0 4.1 auth 8   # trailing comment\nmruby-version 4.0 4.1 hello 3.5\n"
  begin
    entries = parse_accepted(text, 'made_up.txt', names)
    got = entries.map { |e| e.values_at(:condition, :base, :head, :scenario, :allowance, :where) }
    expected = [['mruby-version', '4.0', '4.1', 'auth', 8.0, 'made_up.txt:3'],
                ['mruby-version', '4.0', '4.1', 'hello', 3.5, 'made_up.txt:4']]
    failures << "parse_accepted returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
  rescue PerfError => e
    failures << "parse_accepted rejected a well-formed text: #{e.message}"
    entries = []
  end
  {
    'mruby-version 4.0 4.1 auth' => '4 fields, expected 5',
    'mruby-version 4.0 4.1 auth 8 9' => '6 fields, expected 5',
    'mruby 4.0 4.1 auth 8' => 'unknown condition "mruby"',
    'mruby-version 4.0.0 4.1 auth 8' => '"4.0.0" is not a MAJOR.MINOR version',
    'mruby-version 4.0 4.1 made_up 8' => 'unknown scenario "made_up"',
    'mruby-version 4.0 4.1 auth 8%' => 'allowance "8%" is not a number',
    'mruby-version 4.0 4.1 auth 0' => 'allowance "0" is not a number',
    'mruby-version 4.0 4.1 auth -1' => 'allowance "-1" is not a number',
    'mruby-version 4.0 4.1 auth 0x8' => 'allowance "0x8" is not a number',
    'mruby-version 4.0 4.1 auth 1e1' => 'allowance "1e1" is not a number',
    'mruby-version 4.0 4.1 auth 8_0' => 'allowance "8_0" is not a number',
    'mruby-version 4.0 4.1 auth .5' => 'allowance ".5" is not a number',
    "mruby-version 4.0 4.1 auth 8\nmruby-version 4.0 4.1 auth 9" => 'made_up.txt:2: a second line for mruby-version 4.0 4.1 auth'
  }.each do |bad, message|
    parse_accepted(bad, 'made_up.txt', names)
    failures << "parse_accepted accepted #{bad.inspect}"
  rescue PerfError => e
    failures << "parse_accepted on #{bad.inspect} said #{e.message.inspect}, expected #{message.inspect}" unless e.message.include?(message)
  end
  header = "#define MRUBY_RELEASE_MAJOR 4\n#define MRUBY_RELEASE_MINOR 1\n#define MRUBY_RELEASE_TEENY 0\n"
  { header => '4.1.0', header.sub(/^#define MRUBY_RELEASE_TEENY.*\n/, '') => nil }.each do |text_h, expected|
    got = mruby_version_from(text_h)
    failures << "mruby_version_from gave #{got.inspect}, expected #{expected.inspect}" unless got == expected
  end
  scenario = Scenario.new(name: 'auth', mock: [])
  base = ok.merge(noconst_per_request: 42_599.0)
  [
    # head w/o GC, base and head mruby, expected verdict, expected failed
    [45_622.0, %w[4.0.0 4.1.0], 'ok (accepted: mruby 4.0.0→4.1.0, +8%)', false],
    [43_878.0, %w[4.0.0 4.1.0], 'ok (accepted: mruby 4.0.0→4.1.0, +8%)', false],
    [42_600.0, %w[4.0.0 4.1.0], 'ok', false],
    [46_008.0, %w[4.0.0 4.1.0], 'FAIL', true],
    [45_622.0, %w[4.1.0 4.1.0], 'FAIL', true],
    [45_622.0, %w[4.0.0 4.0.0], 'FAIL', true],
    [45_622.0, [nil, '4.1.0'], 'FAIL', true]
  ].each do |head_judged, versions, expected, expected_failed|
    head = ok.merge(noconst_per_request: head_judged)
    applied = accepted_for(entries, { 'mruby-version' => versions })
    _header, rows, _notes, failed = summarize(builds, [scenario], { %w[base auth] => base, %w[head auth] => head }, applied)
    got = rows.first.last
    next if got == expected && failed == expected_failed

    failures << "auth at #{head_judged} w/o GC with mruby #{versions.inspect} gave #{got.inspect} (failed #{failed}), " \
                "expected #{expected.inspect} (failed #{expected_failed})"
  end
  # The boundary: a change equal to the allowance is accepted, one above it is not.
  allowance = { allowance: 8.0, label: 'mruby 4.0.0→4.1.0' }
  { 8.0 => 'ok (accepted: mruby 4.0.0→4.1.0, +8%)', 8.0001 => 'FAIL' }.each do |change, expected_verdict|
    got = accepted_verdict(change, allowance)
    failures << "accepted_verdict(#{change}) gave #{got.inspect}, expected #{expected_verdict.inspect}" unless got == expected_verdict
  end
  { 'ok (accepted: mruby 4.0.0→4.1.0, +8%)' => 'notice', 'n/a (base: unexpected response)' => 'notice',
    'WARN' => 'warning', 'FAIL' => 'error', 'ERROR' => 'error' }.each do |result, expected_level|
    got = annotation_level(result)
    failures << "annotation_level(#{result.inspect}) gave #{got.inspect}, expected #{expected_level.inspect}" unless got == expected_level
  end
  line = accepted_line({ 'mruby-version' => %w[4.0.0 4.1.0] }, accepted_for(entries, { 'mruby-version' => %w[4.0.0 4.1.0] }))
  file = File.basename(ACCEPTED_FILE)
  expected = "perf: mruby: base 4.0.0, head 4.1.0; accepted differences (#{file}): " \
             'auth up to +8% (mruby 4.0.0→4.1.0), hello up to +3.5% (mruby 4.0.0→4.1.0)'
  failures << "accepted_line gave #{line.inspect}, expected #{expected.inspect}" unless line == expected
  line = accepted_line({ 'mruby-version' => %w[4.1.0 4.1.0] }, {})
  expected = "perf: mruby: base 4.1.0, head 4.1.0; accepted differences (#{file}): none apply"
  failures << "accepted_line without differences gave #{line.inspect}, expected #{expected.inspect}" unless line == expected
  failures + self_test_accepted_pull_request(builds, ok, names, file)
end

# The checks of self_test on the lines of the condition pull-request: their
# reading, PERF_BASE_REF and PERF_PULL_REQUEST, and the verdicts of made-up
# results (the numbers without GC of stream_sleep on #766: base 11459, and
# head 12152 at +6.05%, a FAIL).
def self_test_accepted_pull_request(builds, ok, names, file)
  failures = []
  text = "mruby-version 4.0 4.1 auth 8\npull-request next 766 auth 6\npull-request next 812 hello 3.5\n"
  entries = begin
    parse_accepted(text, 'made_up.txt', names)
  rescue PerfError => e
    failures << "parse_accepted rejected pull-request lines: #{e.message}"
    []
  end
  got = entries.map { |e| e.values_at(:condition, :base, :head, :scenario, :allowance) }
  expected = [['mruby-version', '4.0', '4.1', 'auth', 8.0], ['pull-request', 'next', '766', 'auth', 6.0],
              ['pull-request', 'next', '812', 'hello', 3.5]]
  failures << "parse_accepted returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
  {
    'pull-request next 0766 auth 6' => '"0766" is not a pull request number',
    'pull-request next 766x auth 6' => '"766x" is not a pull request number',
    'pull-request ne$t 766 auth 6' => '"ne$t" is not a branch name',
    'pull-request next 766 auth' => '4 fields, expected 5',
    "pull-request next 766 auth 6\npull-request next 766 auth 7" => 'made_up.txt:2: a second line for pull-request next 766 auth'
  }.each do |bad, message|
    parse_accepted(bad, 'made_up.txt', names)
    failures << "parse_accepted accepted #{bad.inspect}"
  rescue PerfError => e
    failures << "parse_accepted on #{bad.inspect} said #{e.message.inspect}, expected #{message.inspect}" unless e.message.include?(message)
  end
  [
    [{}, nil, nil],
    [{ 'PERF_BASE_REF' => 'next', 'PERF_PULL_REQUEST' => '766' }, %w[next 766], nil],
    [{ 'PERF_BASE_REF' => 'next' }, nil, 'set together'],
    [{ 'PERF_PULL_REQUEST' => '766' }, nil, 'set together'],
    [{ 'PERF_BASE_REF' => 'next', 'PERF_PULL_REQUEST' => 'abc' }, nil, '"abc" is not a pull request number']
  ].each do |env, expected_pr, message|
    got_pr = pull_request_from_env(env)
    failures << "pull_request_from_env(#{env.inspect}) gave #{got_pr.inspect}, expected an error with #{message.inspect}" if message
    failures << "pull_request_from_env(#{env.inspect}) gave #{got_pr.inspect}, expected #{expected_pr.inspect}" unless message || got_pr == expected_pr
  rescue PerfError => e
    failures << "pull_request_from_env(#{env.inspect}) said #{e.message.inspect}, expected #{(message || expected_pr).inspect}" unless message && e.message.include?(message)
  end
  scenario = Scenario.new(name: 'auth', mock: [])
  base = ok.merge(noconst_per_request: 11_459.0)
  accepted_766 = 'ok (accepted: pull request #766 to next, +6%)'
  [
    # head w/o GC, base and head mruby, the pull request, expected verdict, expected failed
    [12_152.0, %w[4.1.0 4.1.0], %w[next 766], 'FAIL', true],                     # +6.05%: above the allowance
    [12_145.0, %w[4.1.0 4.1.0], %w[next 766], accepted_766, false],              # +5.99%
    [11_850.0, %w[4.1.0 4.1.0], %w[next 766], accepted_766, false],              # +3.41%: a WARN within it
    [11_500.0, %w[4.1.0 4.1.0], %w[next 766], 'ok', false],
    [12_145.0, %w[4.1.0 4.1.0], %w[next 767], 'FAIL', true],                     # another pull request
    [12_145.0, %w[4.1.0 4.1.0], %w[master 766], 'FAIL', true],                   # another base
    [12_145.0, %w[4.1.0 4.1.0], nil, 'FAIL', true],                              # not a pull request (a local run)
    [12_145.0, %w[4.0.0 4.1.0], %w[next 766], accepted_766, false],              # the pull-request line, not mruby's 8%
    [12_300.0, %w[4.0.0 4.1.0], %w[next 766], 'FAIL', true],                     # +7.34%: within 8%, above 6%
    [12_300.0, %w[4.0.0 4.1.0], %w[next 767], 'ok (accepted: mruby 4.0.0→4.1.0, +8%)', false]
  ].each do |head_judged, versions, pr, expected, expected_failed|
    head = ok.merge(noconst_per_request: head_judged)
    applied = accepted_for(entries, { 'mruby-version' => versions, 'pull-request' => pr })
    _header, rows, _notes, failed = summarize(builds, [scenario], { %w[base auth] => base, %w[head auth] => head }, applied)
    got = rows.first.last
    next if got == expected && failed == expected_failed

    failures << "auth at #{head_judged} w/o GC with mruby #{versions.inspect} and pull request #{pr.inspect} gave " \
                "#{got.inspect} (failed #{failed}), expected #{expected.inspect} (failed #{expected_failed})"
  end
  # The pull-request line applies whichever line comes first in the file.
  values = { 'mruby-version' => %w[4.0.0 4.1.0], 'pull-request' => %w[next 766] }
  reversed = parse_accepted("pull-request next 766 auth 6\nmruby-version 4.0 4.1 auth 8\n", 'made_up.txt', names)
  [entries, reversed].each do |list|
    got = accepted_for(list, values)['auth']&.values_at(:allowance, :label)
    failures << "accepted_for gave #{got.inspect} for auth, expected [6.0, \"pull request #766 to next\"]" unless got == [6.0, 'pull request #766 to next']
  end
  values = { 'mruby-version' => %w[4.1.0 4.1.0], 'pull-request' => %w[next 766] }
  line = accepted_line(values, accepted_for(entries, values))
  expected = "perf: mruby: base 4.1.0, head 4.1.0; pull request #766 to next; accepted differences (#{file}): " \
             'auth up to +6% (pull request #766 to next)'
  failures << "accepted_line with a pull request gave #{line.inspect}, expected #{expected.inspect}" unless line == expected
  failures
end

def measure(build, scenario)
  nginx = NginxUnderCallgrind.new(build, scenario)
  mock = scenario.mock && MockLLM::Child.new(MOCK_PORT, scenario.mock,
                                             File.join(build.log_dir, "mock.#{scenario.name}.log"))
  result = { problems: [], unit: scenario.mode == :tcp ? 'session' : 'request' }
  dump = client = nil
  started = monotonic
  begin
    mock&.start(START_TIMEOUT)
    nginx.start
    if scenario.mode == :tcp
      StreamClient.check(BACKEND_PORT, scenario.body, io_timeout: IO_TIMEOUT)
    else
      client = Client.new(PORT, io_timeout: IO_TIMEOUT)
      status, headers, body, = scenario_request(client, scenario, close: true)
      client.close
      check_response(scenario, status, headers, body)
    end
    scenario_requests(scenario, WARMUP)&.close
    wait_quiet

    # The window: from here to the dump, on connections of its own.
    wakes = nginx.control('--instr=on')
    client = scenario_requests(scenario, N)
    wakes += nginx.control('--dump')
    dump = nginx.dump_file
    profile = parse_profile(dump, request_functions(scenario), RECORDED_FUNCTIONS)
    check_window(scenario, dump, profile, wakes)
    result.merge!(profile, wakes: wakes,
                           ir_per_request: profile[:ir].to_f / N,
                           nogc_per_request: (profile[:ir] - profile[:gc_ir]).to_f / N,
                           noconst_per_request: noconst_ir(profile).to_f / N,
                           const_unlisted_per_request: profile[:const_unlisted].transform_values { |n| n.to_f / N },
                           const_ir_per_request: profile[:const_ir].to_f / N,
                           gc_calls_per_1000: profile[:gc_calls] * 1000.0 / N,
                           recorded_per_request: profile[:recorded_calls].transform_values { |n| n.to_f / N })
  rescue PerfError, StreamClient::Error, MockLLM::Child::Error, Client::Timeout, SystemCallError, IOError => e
    result[:problems] << "#{e.class}: #{e.message}"
    result[:unexpected_response] = e.is_a?(ResponseError)
  ensure
    client&.close
    result[:problems].concat(nginx.stop(dump))
    result[:problems].concat(mock.stop(STOP_TIMEOUT)) if mock
  end
  result[:seconds] = monotonic - started
  result
end

def percent(base, head)
  (head - base) / base * 100.0
end

def verdict(change)
  if change >= FAIL_PERCENT
    'FAIL'
  elsif change >= WARN_PERCENT
    'WARN'
  else
    'ok'
  end
end

# The accepted differences: test/perf/accepted.txt (its comment has the
# format). PERF_ACCEPTED_FILE names another file, for example an empty one
# to see the verdicts without them.
ACCEPTED_FILE = ENV.fetch('PERF_ACCEPTED_FILE', File.join(ROOT, 'test/perf/accepted.txt'))
ACCEPTED_CONDITIONS = %w[mruby-version pull-request].freeze

# The check of the BASE and HEAD fields of a line, by condition: the
# message when a value is not in the format, or nil.
# - mruby-version: MAJOR.MINOR of the bundled mruby in each build;
# - pull-request: BASE the base branch of the pull request, HEAD its number.
def accepted_value_problem(condition, base, head)
  case condition
  when 'mruby-version'
    [base, head].each do |value|
      return "#{value.inspect} is not a MAJOR.MINOR version such as 4.1" unless value.match?(/\A\d+\.\d+\z/)
    end
  when 'pull-request'
    return "#{base.inspect} is not a branch name such as next" unless base.match?(%r{\A[A-Za-z0-9][A-Za-z0-9._/-]*\z})
    return "#{head.inspect} is not a pull request number such as 812" unless head.match?(/\A[1-9]\d*\z/)
  end
  nil
end

# The lines of an accepted file as hashes (condition, base, head, scenario,
# allowance, where). A line that is not in the format raises PerfError with
# the file and the line number.
def parse_accepted(text, path, scenario_names)
  entries = []
  text.each_line.with_index(1) do |raw, number|
    line = raw.sub(/#.*/, '').strip
    next if line.empty?

    where = "#{path}:#{number}"
    fields = line.split
    unless fields.size == 5
      raise PerfError, "#{where}: #{fields.size} fields, expected 5 (CONDITION BASE HEAD SCENARIO ALLOWANCE): #{line}"
    end

    condition, base, head, scenario, allowance = fields
    unless ACCEPTED_CONDITIONS.include?(condition)
      raise PerfError, "#{where}: unknown condition #{condition.inspect} (known: #{ACCEPTED_CONDITIONS.join(', ')})"
    end
    problem = accepted_value_problem(condition, base, head)
    raise PerfError, "#{where}: #{problem}" if problem
    raise PerfError, "#{where}: unknown scenario #{scenario.inspect}" unless scenario_names.include?(scenario)

    # Decimal digits only: Float() would also take 0x8, 1e1 and 8_0.
    percent = allowance.match?(/\A\d+(?:\.\d+)?\z/) ? Float(allowance) : nil
    unless percent&.positive?
      raise PerfError, "#{where}: allowance #{allowance.inspect} is not a number of percent above 0 (no % sign)"
    end
    if entries.any? { |e| [e[:condition], e[:base], e[:head], e[:scenario]] == [condition, base, head, scenario] }
      raise PerfError, "#{where}: a second line for #{condition} #{base} #{head} #{scenario}"
    end

    entries << { condition: condition, base: base, head: head, scenario: scenario, allowance: percent, where: where }
  end
  entries
end

def load_accepted(path = ACCEPTED_FILE)
  parse_accepted(File.read(path), path, SCENARIOS.map(&:name))
rescue SystemCallError => e
  raise PerfError, "#{path}: #{e.message}"
end

# The version of the bundled mruby (MAJOR.MINOR.TEENY) in the text of
# mruby/include/mruby/version.h, or nil.
def mruby_version_from(text)
  parts = %w[MAJOR MINOR TEENY].map { |part| text[/^#define MRUBY_RELEASE_#{part}\s+(\d+)\s*$/, 1] }
  parts.all? ? parts.join('.') : nil
end

# The mruby version of a build, from the copy of the sources in its tree
# (test/build_release.sh), or nil.
def mruby_version(build)
  path = File.join(build.dir, 'tree/mruby/include/mruby/version.h')
  File.exist?(path) ? mruby_version_from(File.read(path)) : nil
end

# The pull request that the comparison measures, as [base branch, number],
# from PERF_BASE_REF and PERF_PULL_REQUEST (the perf job of test.yml sets
# both), or nil when neither is set. Raises PerfError when only one is set,
# or when a value is not in the format of a line of the accepted file.
def pull_request_from_env(env = ENV)
  base = env['PERF_BASE_REF'].to_s
  number = env['PERF_PULL_REQUEST'].to_s
  return nil if base.empty? && number.empty?
  raise PerfError, 'PERF_BASE_REF and PERF_PULL_REQUEST are set together or not at all' if base.empty? || number.empty?

  problem = accepted_value_problem('pull-request', base, number)
  raise PerfError, "PERF_BASE_REF or PERF_PULL_REQUEST: #{problem}" if problem

  [base, number]
end

# Whether a line matches the [base, head] values of its condition.
def accepted_match?(entry, base, head)
  case entry[:condition]
  when 'mruby-version'
    base.split('.')[0, 2].join('.') == entry[:base] && head.split('.')[0, 2].join('.') == entry[:head]
  when 'pull-request'
    base == entry[:base] && head == entry[:head]
  else
    false
  end
end

# The label of an applied line in the report.
def accepted_label(condition, base, head)
  condition == 'pull-request' ? "pull request ##{head} to #{base}" : "mruby #{base}→#{head}"
end

# The accepted differences that apply to a comparison, by scenario:
# { name => { allowance:, label: } }. values has the [base, head] values
# of each condition ({ 'mruby-version' => ['4.0.0', '4.1.0'],
# 'pull-request' => ['next', '812'] }); a value that is nil (not read, or
# not a pull request) matches no line. When a pull-request line and a
# mruby-version line apply to one scenario, the pull-request line does: it
# is the acceptance of this comparison itself.
def accepted_for(entries, values)
  entries.each_with_object({}) do |e, applied|
    base, head = values[e[:condition]]
    next unless base && head && accepted_match?(e, base, head)

    previous = applied[e[:scenario]]
    if previous
      next if previous[:condition] == 'pull-request' && e[:condition] != 'pull-request'
      unless e[:condition] == 'pull-request' && previous[:condition] != 'pull-request'
        raise PerfError, "#{e[:where]}: a second accepted difference applies to #{e[:scenario]}"
      end
    end
    applied[e[:scenario]] = { allowance: e[:allowance], label: accepted_label(e[:condition], base, head),
                              condition: e[:condition] }
  end
end

# The header line of the report on the accepted differences.
def accepted_line(values, applied)
  base, head = values['mruby-version']
  list = if applied.empty?
           'none apply'
         else
           applied.map { |name, a| "#{name} up to #{format('%+g%%', a[:allowance])} (#{a[:label]})" }.join(', ')
         end
  pr_base, pr_number = values['pull-request']
  pr = pr_number ? "; pull request ##{pr_number} to #{pr_base}" : ''
  "perf: mruby: base #{base || 'unknown'}, head #{head || 'unknown'}#{pr}; " \
    "accepted differences (#{File.basename(ACCEPTED_FILE)}): #{list}"
end

# The verdict of a change with the accepted difference of its scenario (or
# nil): a WARN or FAIL within the allowance is ok (accepted); above it, the
# verdict of the change.
def accepted_verdict(change, accepted)
  v = verdict(change)
  return v if v == 'ok' || accepted.nil? || change > accepted[:allowance]

  "ok (accepted: #{accepted[:label]}, #{format('%+g%%', accepted[:allowance])})"
end

def format_table(header, rows)
  widths = header.each_index.map { |i| ([header] + rows).map { |row| row[i].to_s.size }.max }
  [header, *rows].map do |row|
    row.each_with_index.map { |cell, i| i.zero? ? cell.to_s.ljust(widths[i]) : cell.to_s.rjust(widths[i]) }.join('  ')
  end
end

def fmt_ir(value)
  format('%.0f', value)
end

def fmt_change(value)
  format('%+.2f%%', value)
end

def gc_share(result)
  format('%.1f%%', result[:gc_ir] * 100.0 / result[:ir])
end

# Returns [header, rows, notes, failed]. With two builds, a scenario is
# compared when both measurements succeeded. It is "n/a" when only the base
# failed, with an unexpected response, and its other problems are only
# MRB_RUN_FAILED_LINE lines (a scenario that needs a feature of the head,
# such as a Ruby method or class). Any other failure is an ERROR and fails
# the run, also an unexpected response of the base that came with other
# error.log lines (connect() or recv() errors of the upstream, the line
# saying that a log has more than LOG_LINES_KEPT lines) or with a problem of
# the mock, and so does a run in which no scenario was compared. accepted
# has the accepted differences that apply (accepted_for), by scenario.
def summarize(builds, scenarios, results, accepted = {})
  rows = []
  notes = []
  failed = false
  compared = 0
  scenarios.each do |scenario|
    rs = builds.map { |b| results[[b.label, scenario.name]] }
    ok = rs.map { |r| r[:problems].empty? }
    if builds.size == 1
      r = rs.first
      rows << if ok.first
                [scenario.name, fmt_ir(r[:ir_per_request]), fmt_ir(r[:nogc_per_request]), fmt_ir(r[:noconst_per_request]), gc_share(r),
                 format('%.1f', r[:gc_calls_per_1000]), 'ok']
              else
                [scenario.name, '-', '-', '-', '-', '-', 'ERROR']
              end
      failed ||= !ok.first
      next
    end

    base, head = rs
    if ok.all?
      compared += 1
      total = percent(base[:ir_per_request], head[:ir_per_request])
      nogc = percent(base[:nogc_per_request], head[:nogc_per_request])
      noconst = percent(base[:noconst_per_request], head[:noconst_per_request])
      judged_on = judged_key(base, head) == :nogc_per_request ? 'w/o GC' : 'w/o GC/const'
      v = accepted_verdict(judged_on == 'w/o GC' ? nogc : noconst, accepted[scenario.name])
      failed ||= v == 'FAIL'
      rows << [scenario.name, fmt_ir(base[:ir_per_request]), fmt_ir(head[:ir_per_request]), fmt_change(total),
               fmt_ir(base[:nogc_per_request]), fmt_ir(head[:nogc_per_request]), fmt_change(nogc),
               fmt_ir(base[:noconst_per_request]), fmt_ir(head[:noconst_per_request]), fmt_change(noconst),
               "#{gc_share(base)}/#{gc_share(head)}", judged_on, v]
    elsif ok.last && base[:unexpected_response] && base[:problems].count { |p| !p.match?(MRB_RUN_FAILED_LINE) } == 1
      rows << [scenario.name, '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', 'n/a (base: unexpected response)']
    else
      failed = true
      rows << [scenario.name, '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', 'ERROR']
    end
  end
  if builds.size == 2 && compared.zero?
    failed = true
    notes << 'perf: no scenario was compared'
  end
  header = if builds.size == 1
             ['scenario', 'Ir/req', 'Ir/req w/o GC', 'Ir/req w/o GC/const', 'GC share', 'GC calls/1000 req', 'result']
           else
             ['scenario', "#{builds[0].label} Ir/req", "#{builds[1].label} Ir/req", 'change',
              "#{builds[0].label} w/o GC", "#{builds[1].label} w/o GC", 'change w/o GC',
              "#{builds[0].label} w/o GC/const", "#{builds[1].label} w/o GC/const", 'change w/o GC/const', 'GC share',
              'judged', 'result']
           end
  [header, rows, notes, failed]
end

# The number that judges a scenario: w/o GC/const, or w/o GC when the head
# clears mruby's constant cache more often than the base (CONST_CACHE_CLEARS),
# so that the misses that the clears cause count.
def judged_key(base, head)
  clears = [base, head].map { |r| (r[:recorded_per_request] || {})[:const_clears].to_f }
  clears[1] - clears[0] >= 0.005 ? :nogc_per_request : :noconst_per_request
end

# Lines with the calls per request of RECORDED_FUNCTIONS, which are not
# checked. With two builds, a scenario whose non_buffered_calls differ gets
# the Ir that the difference alone makes, about (NON_BUFFERED_CALL_IR per
# call), as a share of the base without GC; from half of PERF_WARN_PERCENT
# on, the line says that the change of the scenario may come from that.
def recorded_lines(builds, scenarios, results)
  lines = ["perf: calls per request (not checked): #{RECORDED_FUNCTIONS.map { |k, v| "#{k} = #{v.join('/')}" }.join('; ')}"]
  scenarios.each do |scenario|
    rs = builds.map { |b| results[[b.label, scenario.name]] }
    next unless rs.all? { |r| r[:problems].empty? }

    values = RECORDED_FUNCTIONS.keys.map do |key|
      "#{key} #{rs.map { |r| format('%.2f', r[:recorded_per_request][key]) }.join('/')}"
    end
    lines << "perf:   #{scenario.name}: #{values.join(', ')}#{non_buffered_effect(rs)}#{const_miss_effect(rs)}#{const_cost_line(rs)}"
  end
  lines
end

# The note of recorded_lines on the difference of non_buffered_calls
# between base and head ("" with one build or no difference).
def non_buffered_effect(rs)
  return '' unless rs.size == 2

  base, head = rs.map { |r| r[:recorded_per_request][:non_buffered_calls] }
  diff = head - base
  return '' if diff.abs < 0.005

  ir = diff * NON_BUFFERED_CALL_IR
  share = ir / rs[0][:noconst_per_request] * 100.0
  note = format(' (non_buffered_calls %+.2f per request: about %+.0f Ir, %+.2f%% of base w/o GC/const', diff, ir, share)
  note += '; the change of this scenario may come from when the response arrived' if share.abs >= WARN_PERCENT / 2
  "#{note})"
end

# The note of recorded_lines on the difference of const_misses between base
# and head ("" with one build or no difference): the Ir of the constant
# lookups that the judged number leaves out, as a share of the base w/o
# GC/const; from half of PERF_WARN_PERCENT on, the line says that more (or
# fewer) lookups of head miss the constant cache. The misses depend on where
# the ireps were allocated (CONST_LOOKUP_FUNCTIONS), so a change of the code
# can move them, as can another run of the same code.
def const_miss_effect(rs)
  return '' unless rs.size == 2

  base, head = rs.map { |r| r[:recorded_per_request][:const_misses].to_f }
  diff = head - base
  return '' if diff.abs < 0.005

  ir = rs[1][:const_ir_per_request].to_f - rs[0][:const_ir_per_request].to_f
  share = ir / rs[0][:noconst_per_request] * 100.0
  note = format(' (const_misses %+.2f per request: %+.0f Ir, %+.2f%% of base w/o GC/const, not judged', diff, ir, share)
  if share.abs >= WARN_PERCENT / 2
    note += "; #{share.positive? ? 'more' : 'fewer'} constant lookups of head miss the constant cache of mruby"
  end
  "#{note})"
end

# The part of a line of recorded_lines on the cost of the constant lookups
# ("" when there is none): the Ir per request that w/o GC/const leaves out
# in each build, the calls of mrb_vm_const_get that it does not leave out
# (const_unlisted), and which number judges the scenario when the head
# clears the constant cache more often.
def const_cost_line(rs)
  parts = []
  const = rs.map { |r| r[:const_ir_per_request].to_f }
  parts << "const lookups #{const.map { |v| format('%.0f', v) }.join('/')} Ir" if const.any?(&:positive?)
  unlisted = rs.map { |r| r[:const_unlisted_per_request] || {} }
  unlisted.flat_map(&:keys).uniq.sort.each do |name|
    parts << "not subtracted: #{name} #{unlisted.map { |u| format('%.0f', u.fetch(name, 0)) }.join('/')} Ir"
  end
  if rs.size == 2 && judged_key(*rs) == :nogc_per_request
    parts << 'head clears the constant cache of mruby more often: judged w/o GC'
  end
  parts.empty? ? '' : " [#{parts.join('; ')}]"
end

# The reasons of the failed measurements, by scenario: { name => ["base: ...", ...] }.
def reasons_by_scenario(results)
  reasons = Hash.new { |h, k| h[k] = [] }
  results.each do |(label, name), r|
    r[:problems].each { |p| reasons[name] << "#{label}: #{p}" }
  end
  reasons
end

def write_step_summary(header, rows, notes, reasons, accepted_lines = [])
  path = ENV['GITHUB_STEP_SUMMARY']
  return if path.nil? || path.empty?

  File.open(path, 'a') do |f|
    f.puts "### Instructions per request or TCP session (callgrind, N=#{N})"
    f.puts "`stream_sleep` uses one completed TCP session; other rows use an HTTP request."
    f.puts
    f.puts "| #{header.join(' | ')} |"
    f.puts "|#{header.map { '---' }.join('|')}|"
    rows.each { |row| f.puts "| #{row.join(' | ')} |" }
    f.puts
    f.puts "WARN from #{WARN_PERCENT}% and FAIL from #{FAIL_PERCENT}% more Ir per request on the number in the column judged " \
           '(w/o GC/const, or w/o GC where the head clears the constant cache more often).'
    accepted_lines.each { |line| f.puts "\n#{line}" }
    notes.each { |note| f.puts "\n**#{note}**" }
    next if reasons.empty?

    f.puts
    f.puts 'Measurements that failed (n/a and ERROR rows):'
    f.puts
    f.puts '```'
    reasons.each { |name, lines| lines.each { |line| f.puts "#{name} #{line}" } }
    f.puts '```'
  end
end

# The commits of the third-party gems of a build (url => commit), from the
# gem lock that rake wrote, or nil.
def gem_commits(build)
  path = File.join(build.dir, 'tree/build_config.rb.lock')
  return nil unless File.exist?(path)

  host = (YAML.safe_load(File.read(path)) || {}).dig('builds', 'host') || {}
  host.transform_values { |entry| entry['commit'] }
end

# Lines that say whether both builds have the same gems at the same commits.
def gem_lock_lines(builds)
  base, head = builds.map { |b| gem_commits(b) }
  return ['perf: gems: no build_config.rb.lock in a build; cannot compare the gem commits'] unless base && head

  common = base.keys & head.keys
  differ = common.reject { |url| base[url] == head[url] }
  lines = ["perf: gems: #{common.size} in both builds, #{differ.size} at different commits, " \
           "#{(base.keys - head.keys).size} only in base, #{(head.keys - base.keys).size} only in head"]
  differ.each { |url| lines << "perf:   #{url}: base #{base[url].to_s[0, 12]}, head #{head[url].to_s[0, 12]}" }
  lines
end

# The level of the annotation of a row that is not plain ok: a warning for
# WARN, a notice for n/a and for an accepted difference, an error for FAIL
# and ERROR.
def annotation_level(result)
  if result == 'WARN' then 'warning'
  elsif result.start_with?('n/a', 'ok (accepted') then 'notice'
  else 'error'
  end
end

# The message of a workflow command, escaped as GitHub Actions requires.
def workflow_message(text)
  text.to_s.gsub('%', '%25').gsub("\r", '%0D').gsub("\n", '%0A')
end

# Workflow commands that GitHub Actions shows as annotations of the run: an
# error for each FAIL and ERROR row and each note (a run in which no scenario
# was compared), a warning for each WARN row, a notice for each n/a row and
# each row of an accepted difference, with
# the reasons of the failed measurements.
def annotate(header, rows, notes, reasons)
  return unless ENV['GITHUB_ACTIONS'] == 'true'

  rows.each do |row|
    result = row.last
    next if result == 'ok'

    level = annotation_level(result)
    detail = header.zip(row).map { |h, v| "#{h}: #{v}" }.join(', ')
    detail = ([detail] + reasons[row.first]).join("\n") if reasons.key?(row.first)
    puts "::#{level} title=perf #{row.first}::#{workflow_message(detail)}"
  end
  notes.each { |note| puts "::error title=perf::#{workflow_message(note)}" }
end

def selected_scenarios
  names = ENV['PERF_SCENARIOS'].to_s.split(',').map(&:strip).reject(&:empty?)
  names = DEFAULT_SCENARIOS if names.empty?
  names.map do |name|
    scenario = SCENARIOS.find { |s| s.name == name } or
      abort "perf: unknown scenario #{name} (known: #{SCENARIOS.select { |s| %i[keepalive tcp].include?(s.mode) }.map(&:name).join(', ')})"
    abort "perf: scenario #{name} is not a keep-alive or TCP scenario" unless %i[keepalive tcp].include?(scenario.mode)
    scenario
  end
end

if ARGV == ['--self-test']
  failures = self_test
  failures.each { |f| warn "perf: self-test: #{f}" }
  puts "perf: self-test: #{failures.empty? ? 'ok' : "#{failures.size} failed"}"
  exit(failures.empty? ? 0 : 1)
end

labels = ARGV.size == 2 ? %w[base head] : [nil]
abort 'usage: ruby test/perf/perf.rb BUILD_DIR [HEAD_BUILD_DIR] | --self-test' unless [1, 2].include?(ARGV.size)
builds = ARGV.zip(labels).map { |dir, label| Build.new(label || File.basename(File.expand_path(dir)), dir) }
builds.each do |b|
  abort "perf: #{b.nginx_bin} not found; build it with test/perf/run.sh or test/perf/compare.sh" unless File.executable?(b.nginx_bin)
end
# callgrind_control and vgdb, which it runs, work on Linux.
on_path = ->(cmd) { ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, cmd)) } }
unless RUBY_PLATFORM.include?('linux') && %w[valgrind callgrind_control vgdb].all?(&on_path)
  abort 'perf: needs Linux with valgrind, callgrind_control and vgdb on PATH'
end

scenarios = selected_scenarios
# Read before the measurement, so that a line that is not in the format
# stops the run at once.
begin
  accepted_entries = load_accepted
rescue PerfError => e
  abort "perf: #{e.message}"
end
builds.each { |b| b.write_confs(scenarios) }
log("perf: N=#{N} WARMUP=#{WARMUP} PORTS=#{PORT},#{BACKEND_PORT},#{MOCK_PORT} WARN=#{WARN_PERCENT}% FAIL=#{FAIL_PERCENT}%")
builds.each { |b| log("perf: #{b.label}: #{b.dir}") }
gem_lines = builds.size == 2 ? gem_lock_lines(builds) : []
gem_lines.each { |line| log(line) }
begin
  versions = { 'mruby-version' => builds.map { |b| mruby_version(b) }, 'pull-request' => pull_request_from_env }
rescue PerfError => e
  abort "perf: #{e.message}"
end
accepted = {}
accepted_lines = []
if builds.size == 2
  begin
    accepted = accepted_for(accepted_entries, versions)
  rescue PerfError => e
    abort "perf: #{e.message}"
  end
  accepted_lines = [accepted_line(versions, accepted)]
  accepted_lines.each { |line| log(line) }
end
results = {}
scenarios.each do |scenario|
  builds.each do |b|
    r = measure(b, scenario)
    results[[b.label, scenario.name]] = r
    detail = if r[:problems].empty?
               format('%.1f Ir/req, %.1f w/o GC, %.1f w/o GC/const, %s', r[:ir_per_request], r[:nogc_per_request], r[:noconst_per_request],
                      r[:recorded_per_request].map { |k, v| format('%s %.2f/req', k, v) }.join(', '))
             else
               'ERROR'
             end
    log(format('perf: %-11s %-4s %s (%.0f s, %d wake requests)', scenario.name, b.label, detail, r[:seconds], r[:wakes].to_i))
  end
end

header, rows, notes, failed = summarize(builds, scenarios, results, accepted)
lines = format_table(header, rows)
problems = results.reject { |_k, r| r[:problems].empty? }.flat_map do |(label, name), r|
  ["#{name} (#{label}):", *r[:problems].map { |p| "  #{p}" }]
end
report = ["perf: N=#{N} WARMUP=#{WARMUP}; Ir per request of nginx; " \
          "WARN from #{WARN_PERCENT}%, FAIL from #{FAIL_PERCENT}% on the number in the column judged: " \
          'w/o GC/const (Ir/req minus the GC and the constant lookups that missed the cache), or w/o GC (minus the ' \
          'GC only) where the head clears the constant cache more often (const_clears)',
          "perf: units: stream_sleep = completed TCP session; other rows = HTTP request", *gem_lines,
          *accepted_lines, '', *lines]
report += ['', *notes] unless notes.empty?
report += ['', *recorded_lines(builds, scenarios, results)]
report += ['', *problems] unless problems.empty?
log
report.each { |line| log(line) }

FileUtils.mkdir_p(REPORT_DIR)
File.write(File.join(REPORT_DIR, 'report.txt'), "#{report.join("\n")}\n")
json = {
  n: N, warmup: WARMUP, warn_percent: WARN_PERCENT, fail_percent: FAIL_PERCENT,
  builds: builds.map { |b| { label: b.label, dir: b.dir, mruby_version: mruby_version(b) } },
  accepted: accepted.map { |name, a| { scenario: name }.merge(a) },
  results: results.map { |(label, name), r| { build: label, scenario: name }.merge(r) }
}
File.write(File.join(REPORT_DIR, 'report.json'), "#{JSON.pretty_generate(json)}\n")
reasons = reasons_by_scenario(results)
write_step_summary(header, rows, notes, reasons, accepted_lines)
annotate(header, rows, notes, reasons)
exit(failed ? 1 : 0)
