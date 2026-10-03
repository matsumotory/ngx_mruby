# frozen_string_literal: true

# Memory soak test driver for ngx_mruby (CRuby 3.0 or later, Linux).
#
# For each scenario, soak.rb starts the nginx built by test/soak/run.sh, sends
# SOAK_WARMUP requests and then SOAK_N requests in three windows to one
# location, and takes a sample before the first window and after each window.
# A sample is taken while no scenario request is open: Nginx::Debug.stats
# after a full GC, and the worker's VmRSS, open file descriptors and the
# stub_status connection counts. The counters must stay the same from sample
# to sample, and VmRSS must stay within SOAK_RSS_STEP_KB and SOAK_RSS_TOTAL_KB.
# A scenario with a mock LLM upstream (the agent_* scenarios) also starts
# test/soak/mock_llm.rb on port base + 2 and reads its counters. The exit
# status is 1 when any scenario fails.
#
# See docs/test/README.md, "Soak test for memory".

require 'fileutils'
require 'json'
require 'socket'
require_relative 'http_client'
require_relative 'scenarios'

def env_int(name, default)
  value = ENV[name]
  return default if value.nil? || value.empty?

  Integer(value, 10)
end

ROOT = File.expand_path('../..', __dir__)
NGINX_BIN = File.join(ROOT, 'build_soak/nginx/sbin/nginx')
PREFIX = File.join(ROOT, 'build_soak/nginx/soak')
CONF_DIR = File.join(PREFIX, 'conf')
LOG_DIR = File.join(PREFIX, 'logs')
REPORT_PATH = File.join(LOG_DIR, 'soak.log')

PORT = env_int('SOAK_PORT_BASE', 12_360)
BACKEND_PORT = PORT + 1
MOCK_PORT = PORT + 2
N = env_int('SOAK_N', 20_000)
WARMUP = env_int('SOAK_WARMUP', 2000)
CONCURRENCY = env_int('SOAK_CONCURRENCY', 8)
RSS_STEP_KB = env_int('SOAK_RSS_STEP_KB', 512)
RSS_TOTAL_KB = env_int('SOAK_RSS_TOTAL_KB', 1024)
WINDOWS = 3

IO_TIMEOUT = 30       # seconds to wait for one response
START_TIMEOUT = 10    # seconds to wait for the worker and the listening port
QUIET_TIMEOUT = 5     # seconds to wait for the scenario connections to close
STOP_TIMEOUT = 30     # seconds to wait for nginx to exit after SIGQUIT

# Lines in error.log (and nginx's stderr) that fail the scenario. ngx_mruby
# logs an exception raised in a handler at the error level; the :disconnect
# client reads only its first response, so the log is where an exception in
# its later requests shows.
LOG_PATTERNS = ['open socket', '[error]', '[alert]', '[crit]', '[emerg]', 'runtime error:', 'Sanitizer'].freeze

# Values that must be the same in every sample of a scenario. fd_own is the
# number of file descriptors of the worker less the connections that are
# open at the mock LLM (upstream; 0 without a mock): nginx keeps idle
# upstream connections open for the next requests, as many as were in use
# at the same time at the busiest moment so far, so their number can grow by
# one when a later window happens to be busier.
EXACT_KEYS = %i[gc_live gc_root gc_root_fibers gc_arena_idx timers fd_own active].freeze

# Scenarios that run when SOAK_SCENARIOS is not set. A scenario that is
# defined in SCENARIOS (test/soak/scenarios.rb) but left out here runs only
# when SOAK_SCENARIOS names it.
DEFAULT_SCENARIOS = %w[hello headers var filter sleep sub_request file disconnect
                       agent_stream agent_client_abort agent_upstream_reset].freeze

class SoakError < StandardError; end

def log(line = '')
  puts line
  File.open(REPORT_PATH, 'a') { |f| f.puts line }
end

def monotonic
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def children_of(ppid)
  Dir.glob('/proc/[0-9]*/stat').filter_map do |path|
    stat = begin
      File.read(path)
    rescue SystemCallError
      next
    end
    # "pid (comm) state ppid ...": comm may contain spaces and parentheses.
    fields = stat[(stat.rindex(')') + 2)..].split
    path[%r{\A/proc/(\d+)/}, 1].to_i if fields[1].to_i == ppid
  end
end

def vm_rss_kb(pid)
  File.read("/proc/#{pid}/status")[/^VmRSS:\s+(\d+)\s+kB/, 1].to_i
end

def fd_count(pid)
  Dir.children("/proc/#{pid}/fd").size
end

# Writes each template of test/soak/ that the scenarios use to
# PREFIX/conf/<template>.
def write_confs(scenarios)
  FileUtils.mkdir_p(CONF_DIR)
  scenarios.map(&:conf).uniq.each do |template|
    conf = File.read(File.join(__dir__, template))
                .gsub('__SOAK_PORT__', PORT.to_s)
                .gsub('__SOAK_BACKEND_PORT__', BACKEND_PORT.to_s)
                .gsub('__SOAK_MOCK_PORT__', MOCK_PORT.to_s)
                .gsub('__SOAK_HANDLERS__', File.join(__dir__, 'handlers'))
    File.write(File.join(CONF_DIR, template), conf)
  end
end

# A running nginx (master and one worker) for one scenario.
class NginxProcess
  attr_reader :master, :worker

  def initialize(scenario)
    @name = scenario.name
    @conf_path = File.join(CONF_DIR, scenario.conf)
    @allowed_log = scenario.allowed_log
    @error_log = File.join(LOG_DIR, 'error.log')
    @stderr_log = File.join(LOG_DIR, 'stderr.log')
  end

  def start
    FileUtils.rm_f([@error_log, @stderr_log])
    @master = Process.spawn(NGINX_BIN, '-p', "#{PREFIX}/", '-c', @conf_path,
                            %i[out err] => [@stderr_log, 'w'])
    deadline = monotonic + START_TIMEOUT
    loop do
      raise SoakError, "nginx exited at startup:\n#{File.read(@stderr_log)}" if exited?

      workers = children_of(@master)
      if workers.size == 1 && listening?
        @worker = workers.first
        return
      end
      raise SoakError, "no single worker listening on #{PORT} after #{START_TIMEOUT} s" if monotonic > deadline

      sleep 0.05
    end
  end

  # Stops nginx with SIGQUIT. Returns a list of problems (empty when none).
  def stop
    return [] unless @master

    problems = []
    begin
      Process.kill(:QUIT, @master)
    rescue Errno::ESRCH
      nil
    end
    deadline = monotonic + STOP_TIMEOUT
    sleep 0.05 until exited? || monotonic > deadline
    unless exited?
      problems << "nginx did not exit within #{STOP_TIMEOUT} s of SIGQUIT; killed"
      # The children are listed while the master is alive: once it is
      # killed, they are no longer its children. The list includes a worker
      # that the master started after the one found at start.
      ([@master] + children_of(@master)).each do |pid|
        Process.kill(:KILL, pid)
      rescue Errno::ESRCH
        nil
      end
      Process.wait(@master)
    end
    problems << "nginx exited with #{@status.inspect}" if @status && !@status.success?
    @master = nil
    problems + scan_logs
  end

  private

  def exited?
    return true if @status

    pid, status = Process.waitpid2(@master, Process::WNOHANG)
    @status = status if pid
    !pid.nil?
  end

  def listening?
    Socket.tcp('127.0.0.1', PORT, connect_timeout: 1).close
    true
  rescue SystemCallError
    false
  end

  # Keeps the logs of each scenario as error.<scenario>.log and
  # stderr.<scenario>.log, and returns the lines that match LOG_PATTERNS,
  # leaving out the lines that match one of the scenario's allowed_log.
  def scan_logs
    problems = []
    [@error_log, @stderr_log].each do |path|
      next unless File.exist?(path)

      kept = path.sub(/\.log\z/, ".#{@name}.log")
      File.rename(path, kept)
      File.foreach(kept) do |line|
        next if @allowed_log.any? { |allowed| allowed.match?(line) }
        next unless LOG_PATTERNS.any? { |pattern| line.include?(pattern) }

        problems << "#{File.basename(kept)}: #{line.strip}"
        break if problems.size >= 5
      end
    end
    problems
  end
end

def check_response(scenario, status, headers, body)
  return if expected_response?(scenario, status, headers, body)

  raise SoakError, "#{scenario.path}: unexpected response #{status} #{body[0, 200].inspect} #{headers.inspect}"
end

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
ensure
  client&.close
end

# One request per connection for the :abort and :cut scenarios: each
# response is checked (see stream_problem in test/soak/scenarios.rb), and
# the client closes the connection after it.
def stream_requests(scenario, count)
  count.times do
    client = Client.new(PORT, io_timeout: IO_TIMEOUT)
    begin
      problem = stream_problem(client, scenario)
    ensure
      client.close
    end
    raise SoakError, problem if problem
  end
end

# The server holds each :disconnect request until its sleep ends, and the
# client cannot see when that happens. Each thread therefore sends bursts of
# DISCONNECT_BURST requests DISCONNECT_INTERVAL apart, which is longer than the
# 50 ms sleep of /disconnect in nginx.conf. At most CONCURRENCY *
# DISCONNECT_BURST requests are open at once in every window, so the peak
# memory use is reached during the warmup and does not differ between windows.
DISCONNECT_BURST = 16
DISCONNECT_INTERVAL = 0.1

def disconnect_requests(scenario, count)
  sent = 0
  while sent < count
    started = monotonic
    [DISCONNECT_BURST, count - sent].min.times do
      Client.new(PORT, io_timeout: IO_TIMEOUT).send_and_close(scenario.path, scenario.headers)
      sent += 1
    end
    rest = DISCONNECT_INTERVAL - (monotonic - started)
    sleep rest if rest.positive?
  end
end

# Sends count requests over CONCURRENCY connections (or threads, for
# :disconnect) and returns when all of them were sent and, for :keepalive,
# answered. Every connection is closed on return.
#
# When a thread raises, join re-raises its exception here. The other threads
# are stopped and joined before it reaches the caller, which then stops
# nginx: a thread left running could connect to the nginx of the next
# scenario, which listens on the same port, and change its samples.
def send_requests(scenario, count)
  threads = []
  CONCURRENCY.times do |i|
    share = (count / CONCURRENCY) + (i < count % CONCURRENCY ? 1 : 0)
    threads << Thread.new do
      case scenario.mode
      when :disconnect then disconnect_requests(scenario, share)
      when :abort, :cut then stream_requests(scenario, share)
      else keepalive_requests(scenario, share)
      end
    end
  end
  threads.each(&:join)
ensure
  threads.each(&:kill)
  threads.each do |t|
    t.join
  rescue StandardError
    nil # the exception that is propagating, or another thread's
  end
end

def get_closed(path, headers = {})
  client = Client.new(PORT, io_timeout: IO_TIMEOUT)
  client.get(path, headers, close: true)
ensure
  client&.close
end

def stub_status
  status, _headers, body, = get_closed('/status')
  raise SoakError, "/status returned #{status}" unless status == 200

  numbers = body.scan(/\d+/).map(&:to_i)
  # Active connections: A / accepts handled requests / Reading: R Writing: W Waiting: I
  { active: numbers[0], requests: numbers[3], reading: numbers[4], writing: numbers[5], waiting: numbers[6] }
end

# Whether nginx may keep idle connections to the mock open between requests:
# in :abort and :cut scenarios no response ends normally, so nginx closes
# every upstream connection.
def idle_upstream?(scenario)
  scenario.mode == :keepalive
end

# Waits until the only open connection is the one asking /status, then reads
# Nginx::Debug.stats and the worker's /proc entries. With a mock, also reads
# how many connections are open at the mock (upstream); in a scenario where
# nginx keeps none (idle_upstream?), first waits until there are none.
def take_sample(nginx, mock, scenario)
  deadline = monotonic + QUIET_TIMEOUT
  status = nil
  loop do
    status = stub_status
    status[:quiet] = status[:active] == 1 && status[:reading].zero? && status[:writing] == 1 && status[:waiting].zero?
    break if status[:quiet] || monotonic > deadline

    sleep 0.01
  end

  code, _headers, body, = get_closed('/debug/stats')
  raise SoakError, "/debug/stats returned #{code}: #{body}" unless code == 200

  stats = JSON.parse(body, symbolize_names: true)
  upstream = 0
  if mock
    loop do
      upstream = mock.stats[:connections_open]
      break if idle_upstream?(scenario) || upstream.zero? || monotonic > deadline

      sleep 0.01
    end
  end
  fd = fd_count(nginx.worker)
  stats.merge(status).merge(rss_kb: vm_rss_kb(nginx.worker), fd: fd, upstream: upstream, fd_own: fd - upstream)
end

def judge(samples, scenario)
  problems = []
  samples.each_with_index do |s, i|
    problems << "sample #{i}: connections still open after #{QUIET_TIMEOUT} s (#{s.slice(:active, :reading, :writing, :waiting)})" unless s[:quiet]
    problems << "sample #{i}: #{s[:timers]} timers pending with no request open" unless s[:timers].zero?
    limit = idle_upstream?(scenario) ? CONCURRENCY : 0
    problems << "sample #{i}: #{s[:upstream]} connections open at the mock (limit #{limit})" if s[:upstream] > limit
  end
  EXACT_KEYS.each do |key|
    values = samples.map { |s| s[key] }
    problems << "#{key} changed: #{values.join(' -> ')}" if values.uniq.size > 1
  end
  rss = samples.map { |s| s[:rss_kb] }
  step = rss[-1] - rss[-2]
  total = rss[-1] - rss[0]
  problems << "VmRSS grew #{step} kB in the last window (limit #{RSS_STEP_KB})" if step > RSS_STEP_KB
  problems << "VmRSS grew #{total} kB from the first sample (limit #{RSS_TOTAL_KB})" if total > RSS_TOTAL_KB
  problems
end

# One checked response before the warmup: for :disconnect, it is the only
# response the client reads.
def first_response(scenario)
  client = Client.new(PORT, io_timeout: IO_TIMEOUT)
  case scenario.mode
  when :abort, :cut
    problem = stream_problem(client, scenario)
    raise SoakError, problem if problem
  when :disconnect
    check_response(scenario, *client.get(scenario.path, scenario.headers, close: true).first(3))
  else
    check_response(scenario, *scenario_request(client, scenario, close: true).first(3))
  end
ensure
  client&.close
end

# The mock's counters after the last sample: every request reached it once,
# and each ended as the scenario's mode makes it end (written in full; held
# until nginx closed the connection, or found closed while writing; reset).
def mock_problems(scenario, stats, sent)
  ended = case scenario.mode
          when :abort then { 'held until nginx closed it or found closed while writing' => stats[:held_closed] + stats[:write_failed] }
          when :cut then { 'reset' => stats[:reset] }
          else { 'written in full' => stats[:completed] }
          end
  problems = []
  problems << "the mock read #{stats[:requests]} requests, #{sent} were sent" unless stats[:requests] == sent
  ended.each { |what, n| problems << "#{n} of #{sent} answers of the mock #{what}" unless n == sent }
  problems << "#{stats[:held]} streams still held at the mock" unless stats[:held].zero?
  problems
end

def run_scenario(scenario)
  nginx = NginxProcess.new(scenario)
  mock = scenario.mock && MockLLM::Child.new(MOCK_PORT, scenario.mock, File.join(LOG_DIR, "mock.#{scenario.name}.log"))
  samples = []
  problems = []
  started = monotonic
  begin
    mock&.start(START_TIMEOUT)
    nginx.start
    first_response(scenario)

    send_requests(scenario, WARMUP)
    samples << take_sample(nginx, mock, scenario)
    WINDOWS.times do |w|
      send_requests(scenario, (N * (w + 1) / WINDOWS) - (N * w / WINDOWS))
      samples << take_sample(nginx, mock, scenario)
    end
    problems.concat(judge(samples, scenario))
    problems.concat(mock_problems(scenario, mock.stats, 1 + WARMUP + N)) if mock
  rescue SoakError, MockLLM::Child::Error, Client::Timeout, SystemCallError, IOError, JSON::ParserError => e
    problems << "#{e.class}: #{e.message}"
  ensure
    problems.concat(nginx.stop)
    problems.concat(mock.stop(STOP_TIMEOUT)) if mock
  end
  { scenario: scenario, samples: samples, problems: problems, seconds: monotonic - started }
end

def format_values(values)
  values.uniq.size == 1 ? values.first.to_s : values.join('/')
end

def report(results)
  header = %w[scenario result secs requests gc_live gc_root fibers arena timers fd up active rss_kb rss_step rss_total]
  rows = results.map do |r|
    s = r[:samples]
    full = s.size == WINDOWS + 1
    rss = s.map { |x| x[:rss_kb] }
    [
      r[:scenario].name,
      r[:problems].empty? ? 'pass' : 'FAIL',
      format('%.1f', r[:seconds]),
      full ? s.last[:requests].to_s : '-',
      *%i[gc_live gc_root gc_root_fibers gc_arena_idx timers fd upstream active].map { |k| full ? format_values(s.map { |x| x[k] }) : '-' },
      full ? rss.join(' ') : '-',
      full ? format('%+d', rss[-1] - rss[-2]) : '-',
      full ? format('%+d', rss[-1] - rss[0]) : '-'
    ]
  end
  widths = header.each_index.map { |i| ([header] + rows).map { |row| row[i].size }.max }
  log
  log([header, *rows].map { |row| row.each_with_index.map { |cell, i| cell.ljust(widths[i]) }.join('  ').rstrip })
  results.reject { |r| r[:problems].empty? }.each do |r|
    log
    log("#{r[:scenario].name}:")
    r[:problems].each { |p| log("  #{p}") }
  end
end

def selected_scenarios
  names = ENV['SOAK_SCENARIOS'].to_s.split(',').map(&:strip).reject(&:empty?)
  names = DEFAULT_SCENARIOS if names.empty?
  names.map do |name|
    SCENARIOS.find { |s| s.name == name } or abort "soak: unknown scenario #{name} (known: #{SCENARIOS.map(&:name).join(', ')})"
  end
end

abort "soak: #{NGINX_BIN} not found; run test/soak/run.sh without ONLY_RUN first" unless File.executable?(NGINX_BIN)
abort 'soak: Linux only (reads /proc)' unless File.directory?('/proc/self/fd')

Thread.report_on_exception = false
FileUtils.mkdir_p(LOG_DIR)
# Logs of an earlier run would be mistaken for logs of this one.
FileUtils.rm_f(Dir.glob(File.join(LOG_DIR, '{error,stderr,mock}.*.log')))
File.write(REPORT_PATH, '')
scenarios = selected_scenarios
write_confs(scenarios)
log("soak: N=#{N} WARMUP=#{WARMUP} CONCURRENCY=#{CONCURRENCY} PORTS=#{PORT},#{BACKEND_PORT},#{MOCK_PORT} " \
    "RSS_STEP_KB=#{RSS_STEP_KB} RSS_TOTAL_KB=#{RSS_TOTAL_KB}")
results = scenarios.map do |scenario|
  log("soak: #{scenario.name} ...")
  run_scenario(scenario)
end
report(results)
exit(results.all? { |r| r[:problems].empty? } ? 0 : 1)
