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
# (test/soak/nginx.conf, with master_process off) under
# `valgrind --tool=callgrind --instr-atstart=no`, checks one response, sends
# PERF_WARMUP requests, switches the instrumentation on with
# callgrind_control, sends PERF_N requests over keep-alive, dumps the profile
# with callgrind_control, and stops nginx. The dump holds the cost of the
# PERF_N requests and nothing else; Ir per request is its Ir divided by
# PERF_N. The GC-excluded number leaves out the calls into mrb_incremental_gc
# and mrb_full_gc. A window with 0 Ir, or without the expected number of
# calls of the scenario's request function (ngx_mrb_start_fiber for the
# scenarios of test/soak/nginx.conf; see REQUEST_FUNCTIONS and
# request_functions), fails the measurement.
#
# The agent proxy scenarios (proxy_*, auth, route_json_*, ruby_call_*) use
# the template test/soak/nginx.agent.conf, and those with an upstream also
# get the mock LLM test/soak/mock_llm.rb on port base + 2, started before
# nginx and stopped after it.
#
# Why master_process off: callgrind_control reaches a process through
# valgrind's gdbserver (vgdb), and vgdb does not serve a process that valgrind
# forked, such as an nginx worker. With master_process off, the one nginx
# process runs the event loop and the request handlers as a worker does.
#
# With two builds, the change of head against base is judged per scenario on
# the GC-excluded number: WARN from PERF_WARN_PERCENT, FAIL from
# PERF_FAIL_PERCENT. The exit status is 1 when a scenario is FAIL, when a
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

# The scenarios measured when PERF_SCENARIOS is not set: keep-alive
# scenarios of test/soak/scenarios.rb. proxy_stream_plain_1000 and
# route_json_64k are left out for their time (see docs/test/README.md);
# PERF_SCENARIOS names them.
DEFAULT_SCENARIOS = %w[hello headers var filter sleep sub_request file
                       proxy_plain_2k proxy_plain_64k proxy_stream_plain_50 auth route_json_2k
                       ruby_call_1 ruby_call_10].freeze

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
SCENARIO_REQUEST_FUNCTIONS = { 'ruby_call_1' => SET_CODE_FUNCTIONS, 'ruby_call_10' => SET_CODE_FUNCTIONS }.freeze

# Functions whose calls per request are reported but not checked:
# - ruby_calls: the Ruby runs. ngx_mrb_run starts a fiber for each run of
#   Ruby code, and nothing else calls ngx_mrb_start_fiber; callgrind records
#   these calls also where it misses one of ngx_mrb_run (SET_CODE_FUNCTIONS).
#   In the scenarios of test/soak/nginx.conf, the request function counts
#   the same calls (REQUEST_FUNCTIONS).
# - non_buffered_calls: the calls of
#   ngx_http_upstream_process_non_buffered_request, which relays an
#   unbuffered response. nginx calls it when the upstream connection is
#   readable and when the client connection is writable; one call reads
#   from the upstream until recv() would block, up to proxy_buffer_size at a
#   time, and writes what it read to the client. How many calls a response
#   takes depends on how much of it had arrived at each call, that is on
#   timing, and each call costs Ir (NON_BUFFERED_CALL_IR).
RECORDED_FUNCTIONS = { ruby_calls: %w[ngx_mrb_start_fiber],
                       non_buffered_calls: %w[ngx_http_upstream_process_non_buffered_request] }.freeze

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

# Sends count requests over keep-alive (a new connection when nginx closes
# one, after keepalive_requests) and checks every response. Returns the open
# client, so that closing it is not part of the measured window.
def keepalive_requests(scenario, count)
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
# calls into the GC, and the number of calls of the request function: calls
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
        request_calls += call_count if functions.include?(base_name(cfn)) && !functions.include?(base_name(fn))
        recorded.each do |key, list|
          recorded_calls[key] += call_count if list.include?(base_name(cfn)) && !list.include?(base_name(fn))
        end
        call_count = nil
      else
        self_ir += ir
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

  result = { ir: totals, gc_ir: gc_ir, gc_calls: gc_calls, request_calls: request_calls }
  result[:recorded_calls] = recorded_calls unless recorded.empty?
  result
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
  summary: 86

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

  totals: 86
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
    # mrb_incremental_gc'2 are not counted again.
    # The list is given, not taken from REQUEST_FUNCTIONS, so that the
    # self-test does not depend on PERF_REQUEST_FUNCTIONS.
    expected = { ir: 86, gc_ir: 40, gc_calls: 2, request_calls: 4 }
    got = parse_profile(path, %w[ngx_mrb_run])
    failures << "parse_profile returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
    # Another request function, and recorded functions: the handler calls
    # ngx_mrb_run_fiber twice; nothing calls ngx_http_log_request.
    expected = expected.merge(request_calls: 2, recorded_calls: { ruby_calls: 4, log: 0 })
    got = parse_profile(path, %w[ngx_mrb_run_fiber], { ruby_calls: %w[ngx_mrb_run], log: %w[ngx_http_log_request] })
    failures << "parse_profile with other functions returned #{got.inspect}, expected #{expected.inspect}" unless got == expected
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
  ok = { problems: [], ir_per_request: 50_000.0, nogc_per_request: 50_000.0, gc_ir: 0, ir: 1,
         recorded_per_request: { ruby_calls: 0.0, non_buffered_calls: 5.0 } }
  unexpected = 'ResponseError: /v1/plain: unexpected response 502'
  connect = 'error.made_up.log: [error] connect() failed (111: Connection refused) while connecting to upstream'
  # What ngx_mrb_raise_error logs when the base lacks a method that the
  # scenario calls (the form of a line from a real run).
  mrb_run_failed = 'error.made_up.log: 2026/10/03 22:59:25 [error] 7#0: *2 mrb_run failed: return 500 HTTP status code ' \
                   "to client: error: undefined method 'made_up' (NoMethodError), client: 127.0.0.1, server: , " \
                   'request: "POST /v1/plain HTTP/1.1", host: "localhost"'
  [
    ['n/a (base: unexpected response)', [unexpected]],
    ['ERROR', [unexpected, connect]],
    ['n/a (base: unexpected response)', [unexpected, mrb_run_failed]],
    ['ERROR', [unexpected, mrb_run_failed, connect]],
    ['ERROR', [unexpected, mrb_run_failed, log_more_lines('error.made_up.log')]]
  ].each do |expected, problems|
    base = { problems: problems, unexpected_response: true }
    _header, rows, = summarize(builds, [scenario], { %w[base made_up] => base, %w[head made_up] => ok })
    got = rows.first.last
    failures << "summarize with base problems #{problems.inspect} gave #{got.inspect}, expected #{expected.inspect}" unless got == expected
  end
  {
    5.0 => '', 5.08 => '+0.08 per request: about +80 Ir, +0.16% of base w/o GC)',
    6.6 => '+1.60 per request: about +1600 Ir, +3.20% of base w/o GC; the change of this scenario may come from when the response arrived)'
  }.each do |head_calls, expected|
    head = ok.merge(recorded_per_request: { ruby_calls: 0.0, non_buffered_calls: head_calls })
    got = non_buffered_effect([ok, head])
    failures << "non_buffered_effect with #{head_calls} calls gave #{got.inspect}, expected one ending #{expected.inspect}" unless got.end_with?(expected)
  end
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
  failures
end

def measure(build, scenario)
  nginx = NginxUnderCallgrind.new(build, scenario)
  mock = scenario.mock && MockLLM::Child.new(MOCK_PORT, scenario.mock,
                                             File.join(build.log_dir, "mock.#{scenario.name}.log"))
  result = { problems: [] }
  dump = client = nil
  started = monotonic
  begin
    mock&.start(START_TIMEOUT)
    nginx.start
    client = Client.new(PORT, io_timeout: IO_TIMEOUT)
    status, headers, body, = scenario_request(client, scenario, close: true)
    client.close
    check_response(scenario, status, headers, body)
    keepalive_requests(scenario, WARMUP)&.close
    wait_quiet

    # The window: from here to the dump, on connections of its own.
    wakes = nginx.control('--instr=on')
    client = keepalive_requests(scenario, N)
    wakes += nginx.control('--dump')
    dump = nginx.dump_file
    profile = parse_profile(dump, request_functions(scenario), RECORDED_FUNCTIONS)
    check_window(scenario, dump, profile, wakes)
    result.merge!(profile, wakes: wakes,
                           ir_per_request: profile[:ir].to_f / N,
                           nogc_per_request: (profile[:ir] - profile[:gc_ir]).to_f / N,
                           gc_calls_per_1000: profile[:gc_calls] * 1000.0 / N,
                           recorded_per_request: profile[:recorded_calls].transform_values { |n| n.to_f / N })
  rescue PerfError, MockLLM::Child::Error, Client::Timeout, SystemCallError, IOError => e
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
# the mock, and so does a run in which no scenario was compared.
def summarize(builds, scenarios, results)
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
                [scenario.name, fmt_ir(r[:ir_per_request]), fmt_ir(r[:nogc_per_request]), gc_share(r),
                 format('%.1f', r[:gc_calls_per_1000]), 'ok']
              else
                [scenario.name, '-', '-', '-', '-', 'ERROR']
              end
      failed ||= !ok.first
      next
    end

    base, head = rs
    if ok.all?
      compared += 1
      total = percent(base[:ir_per_request], head[:ir_per_request])
      nogc = percent(base[:nogc_per_request], head[:nogc_per_request])
      v = verdict(nogc)
      failed ||= v == 'FAIL'
      rows << [scenario.name, fmt_ir(base[:ir_per_request]), fmt_ir(head[:ir_per_request]), fmt_change(total),
               fmt_ir(base[:nogc_per_request]), fmt_ir(head[:nogc_per_request]), fmt_change(nogc),
               "#{gc_share(base)}/#{gc_share(head)}", v]
    elsif ok.last && base[:unexpected_response] && base[:problems].count { |p| !p.match?(MRB_RUN_FAILED_LINE) } == 1
      rows << [scenario.name, '-', '-', '-', '-', '-', '-', '-', 'n/a (base: unexpected response)']
    else
      failed = true
      rows << [scenario.name, '-', '-', '-', '-', '-', '-', '-', 'ERROR']
    end
  end
  if builds.size == 2 && compared.zero?
    failed = true
    notes << 'perf: no scenario was compared'
  end
  header = if builds.size == 1
             ['scenario', 'Ir/req', 'Ir/req w/o GC', 'GC share', 'GC calls/1000 req', 'result']
           else
             ['scenario', "#{builds[0].label} Ir/req", "#{builds[1].label} Ir/req", 'change',
              "#{builds[0].label} w/o GC", "#{builds[1].label} w/o GC", 'change w/o GC', 'GC share', 'result']
           end
  [header, rows, notes, failed]
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
    lines << "perf:   #{scenario.name}: #{values.join(', ')}#{non_buffered_effect(rs)}"
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
  share = ir / rs[0][:nogc_per_request] * 100.0
  note = format(' (non_buffered_calls %+.2f per request: about %+.0f Ir, %+.2f%% of base w/o GC', diff, ir, share)
  note += '; the change of this scenario may come from when the response arrived' if share.abs >= WARN_PERCENT / 2
  "#{note})"
end

# The reasons of the failed measurements, by scenario: { name => ["base: ...", ...] }.
def reasons_by_scenario(results)
  reasons = Hash.new { |h, k| h[k] = [] }
  results.each do |(label, name), r|
    r[:problems].each { |p| reasons[name] << "#{label}: #{p}" }
  end
  reasons
end

def write_step_summary(header, rows, notes, reasons)
  path = ENV['GITHUB_STEP_SUMMARY']
  return if path.nil? || path.empty?

  File.open(path, 'a') do |f|
    f.puts "### Instructions per request (callgrind, N=#{N})"
    f.puts
    f.puts "| #{header.join(' | ')} |"
    f.puts "|#{header.map { '---' }.join('|')}|"
    rows.each { |row| f.puts "| #{row.join(' | ')} |" }
    f.puts
    f.puts "WARN from #{WARN_PERCENT}% and FAIL from #{FAIL_PERCENT}% more Ir per request without the GC."
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

# The message of a workflow command, escaped as GitHub Actions requires.
def workflow_message(text)
  text.to_s.gsub('%', '%25').gsub("\r", '%0D').gsub("\n", '%0A')
end

# Workflow commands that GitHub Actions shows as annotations of the run: an
# error for each FAIL and ERROR row and each note (a run in which no scenario
# was compared), a warning for each WARN row, a notice for each n/a row, with
# the reasons of the failed measurements.
def annotate(header, rows, notes, reasons)
  return unless ENV['GITHUB_ACTIONS'] == 'true'

  rows.each do |row|
    result = row.last
    next if result == 'ok'

    level = if result == 'WARN' then 'warning'
            elsif result.start_with?('n/a') then 'notice'
            else 'error'
            end
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
      abort "perf: unknown scenario #{name} (known: #{SCENARIOS.select { |s| s.mode == :keepalive }.map(&:name).join(', ')})"
    abort "perf: scenario #{name} is not a keep-alive scenario" unless scenario.mode == :keepalive
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
builds.each { |b| b.write_confs(scenarios) }
log("perf: N=#{N} WARMUP=#{WARMUP} PORTS=#{PORT},#{BACKEND_PORT},#{MOCK_PORT} WARN=#{WARN_PERCENT}% FAIL=#{FAIL_PERCENT}%")
builds.each { |b| log("perf: #{b.label}: #{b.dir}") }
gem_lines = builds.size == 2 ? gem_lock_lines(builds) : []
gem_lines.each { |line| log(line) }
results = {}
scenarios.each do |scenario|
  builds.each do |b|
    r = measure(b, scenario)
    results[[b.label, scenario.name]] = r
    detail = if r[:problems].empty?
               format('%.1f Ir/req, %.1f w/o GC, %s', r[:ir_per_request], r[:nogc_per_request],
                      r[:recorded_per_request].map { |k, v| format('%s %.2f/req', k, v) }.join(', '))
             else
               'ERROR'
             end
    log(format('perf: %-11s %-4s %s (%.0f s, %d wake requests)', scenario.name, b.label, detail, r[:seconds], r[:wakes].to_i))
  end
end

header, rows, notes, failed = summarize(builds, scenarios, results)
lines = format_table(header, rows)
problems = results.reject { |_k, r| r[:problems].empty? }.flat_map do |(label, name), r|
  ["#{name} (#{label}):", *r[:problems].map { |p| "  #{p}" }]
end
report = ["perf: N=#{N} WARMUP=#{WARMUP}; Ir per request of nginx; " \
          "WARN from #{WARN_PERCENT}%, FAIL from #{FAIL_PERCENT}% on the number without GC", *gem_lines, '', *lines]
report += ['', *notes] unless notes.empty?
report += ['', *recorded_lines(builds, scenarios, results)]
report += ['', *problems] unless problems.empty?
log
report.each { |line| log(line) }

FileUtils.mkdir_p(REPORT_DIR)
File.write(File.join(REPORT_DIR, 'report.txt'), "#{report.join("\n")}\n")
json = {
  n: N, warmup: WARMUP, warn_percent: WARN_PERCENT, fail_percent: FAIL_PERCENT,
  builds: builds.map { |b| { label: b.label, dir: b.dir } },
  results: results.map { |(label, name), r| { build: label, scenario: name }.merge(r) }
}
File.write(File.join(REPORT_DIR, 'report.json'), "#{JSON.pretty_generate(json)}\n")
reasons = reasons_by_scenario(results)
write_step_summary(header, rows, notes, reasons)
annotate(header, rows, notes, reasons)
exit(failed ? 1 : 0)
