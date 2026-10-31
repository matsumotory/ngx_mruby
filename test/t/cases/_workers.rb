#!/usr/bin/env ruby
# Runs nginx with a master process and several worker processes, sends it
# requests, reloads it, stops it, and prints what it observed. The test nginx
# of test.sh is a single process (master_process off), and the test build of
# mruby has no Process module, so test/t/cases/workers.rb runs this file with
# CRuby, as other cases run test/t/cases/_second_instance.rb (see "Several
# workers and reloads" in docs/test/README.md).
#
# Usage: ruby test/t/cases/_workers.rb isolation|reload
#
# NGINX_INSTALL_DIR names the nginx that test.sh installed. The nginx of a
# mode uses the prefix NGINX_INSTALL_DIR/workers/MODE/ and the configuration
# test/conf/workers/MODE.conf of the copy of the suite that test.sh runs, in
# which TEST_SH_PORT_OFFSET has moved the ports. It writes its error log to
# NGINX_INSTALL_DIR/logs/workers_MODE.error.log, and its standard output and
# error to logs/workers_MODE.stderr.log, where the sanitizer check of CI
# reads them. It runs under NGINX_RUNNER when that is set and not "exec", as
# the test nginx does: valgrind follows the fork of each worker, and with
# "%p" in --log-file each process gets a log of its own.
#
# isolation: four workers. The script sends requests to /worker, one per
#   connection, until every worker has answered at least twice (at most 200
#   requests).
# reload: two workers. The script starts a request to /sleep and a stream
#   session, whose handlers sleep until the file "release" exists, writes
#   the configuration of generation 2 and a new script.rb, sends SIGHUP to
#   the master, waits until generation 2 answers and every old worker has
#   logged "gracefully shutting down", then writes "release" and reads the
#   answers of the two sleeps.
#
# The script prints one "key=value" line for each observation; the key
# response comes once for each request. The keys:
#   workers         the pids of the workers after the start, joined by ","
#   master          the pid of the master process that the script started
#   pid_file        the pid in the pid file of that nginx
#   response        isolation: "STATUS|BODY" of each request, in order
#   requests        isolation: the number of requests
#   before, script_before  reload: "STATUS|BODY" of /generation and /script
#                   before the reload
#   http_sleep_worker, stream_sleep_worker  reload: the pid of the worker
#                   that logged the start of each sleep
#   after, script_after  reload: "STATUS|BODY" of /generation and /script
#                   once generation 2 answers
#   in_flight       reload: the sleeps that had not answered when every old
#                   worker had logged "gracefully shutting down", joined by ","
#   old_alive       reload: the old workers that still ran at that moment,
#                   joined by ","; an old worker without a sleep in flight
#                   may have ended already
#   http_in_flight  reload: "STATUS|BODY" of /sleep after "release"
#   stream_in_flight  reload: the bytes of the stream session after "release"
#   http_order, stream_order  reload: the order in the error log of the
#                   worker's "gracefully shutting down" and the "resumed" line
#                   of its sleep; "shutdown,resumed" when the worker began to
#                   shut down while the sleep was in flight
#   old_ended       reload: "N of M": how many old workers ended after
#                   "release"
#   new_workers     reload: the pids of the workers of generation 2
#   after_release   reload: "STATUS|BODY" of /generation after "release"
#   stream_after    reload: the bytes of a stream session to generation 2
#   exit            how the stop went: "master exited N; M of K workers
#                   ended", K counting the workers of every generation
#   error_lines     the number of lines of the error log at the level error
#                   or above (error, crit, alert, emerg)
#   error_line      the first such line, when there is one
#   sanitizer       the first sanitizer line of the error log or of the
#                   stderr log, when there is one
#   valgrind        under valgrind with "%p" in --log-file, once for the
#                   master and once for each worker: "PID:N", N the errors
#                   that its ERROR SUMMARY counts, or "PID:no summary"
#   seconds         the time of the whole run
#   error           only when a step failed; the keys of the later steps are
#                   then missing

require 'socket'
require 'fileutils'

# The upper bound, in seconds, of each wait. A wait ends as soon as its
# condition holds, so the bound counts only when nginx hangs. Under valgrind
# a start or a reload takes a few seconds ("Waiting for nginx to listen" in
# docs/test/README.md has the times of the test nginx).
LIMIT = Float(ENV['NGINX_HEATTIME'] || 60)

MODES = {
  'isolation' => { workers: 4, http: [18180], stream: [] },
  'reload' => { workers: 2, http: [18181], stream: [12379] },
}.freeze

ERROR_LEVEL = /\[(error|crit|alert|emerg)\]/.freeze
SANITIZER = /ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)/.freeze

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def out(key, value)
  puts "#{key}=#{value.to_s.gsub("\n", '\\n')}"
  $stdout.flush
end

# Calls the block every 0.05 seconds until it returns a true value, and
# returns that value; fails after LIMIT seconds.
def wait_until(what)
  deadline = now + LIMIT
  loop do
    value = yield
    return value if value
    raise "#{what}: not within #{LIMIT} seconds" if now > deadline

    sleep 0.05
  end
end

def port_open?(port)
  TCPSocket.new('127.0.0.1', port).close
  true
rescue Errno::ECONNREFUSED
  false
end

def read_until_close(sock)
  deadline = now + LIMIT
  data = ''.b
  loop do
    remaining = deadline - now
    raise "no close from nginx within #{LIMIT} seconds" if remaining <= 0
    next unless IO.select([sock], nil, nil, remaining)

    chunk = sock.read_nonblock(4096, exception: false)
    return data if chunk.nil?
    next if chunk == :wait_readable

    data << chunk
  end
end

# One TCP connection: sends the payload and reads until nginx closes.
def exchange(port, payload = '')
  Socket.tcp('127.0.0.1', port, connect_timeout: LIMIT) do |sock|
    sock.write(payload) unless payload.empty?
    read_until_close(sock)
  end
end

# One HTTP/1.0 request on a connection of its own: "STATUS|BODY".
def get(port, path)
  raw = exchange(port, "GET #{path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
  head, body = raw.split("\r\n\r\n", 2)
  "#{head.to_s.split("\r\n")[0].to_s.split(' ')[1]}|#{body}"
end

# pid => parent pid, state and command line, for every process.
def processes
  `ps -A -ww -o pid= -o ppid= -o stat= -o args=`.split("\n").each_with_object({}) do |line, all|
    pid, ppid, stat, args = line.strip.split(/\s+/, 4)
    all[pid.to_i] = { ppid: ppid.to_i, stat: stat.to_s, args: args.to_s }
  end
end

class WorkersNginx
  attr_reader :pid

  def initialize(mode)
    @spec = MODES.fetch(mode)
    @install = ENV.fetch('NGINX_INSTALL_DIR')
    @prefix = File.join(@install, 'workers', mode) + '/'
    @conf = File.join(@prefix, 'nginx.conf')
    @template = File.read(File.expand_path("../../conf/workers/#{mode}.conf", __dir__))
    @error_log = File.join(@install, 'logs', "workers_#{mode}.error.log")
    @stderr_log = File.join(@install, 'logs', "workers_#{mode}.stderr.log")
    @pid = nil
    @status = nil
    @seen = [] # every worker pid seen, of every generation
  end

  def prefix_path(name)
    File.join(@prefix, name)
  end

  def write_conf(generation)
    so = File.join(@install, 'modules', 'ngx_http_mruby_module.so')
    body = @template.gsub('__GENERATION__', generation.to_s).gsub('__PREFIX__', @prefix)
    File.write(@conf, [
      File.exist?(so) ? "load_module #{so};" : '',
      'daemon off;',
      'master_process on;',
      "worker_processes #{@spec[:workers]};",
      # A master that runs as root (in a container) starts its workers as
      # nobody, who may not read the files of the prefix.
      Process.euid.zero? ? 'user root;' : '',
      "pid #{prefix_path('nginx.pid')};",
      "error_log #{@error_log} notice;",
      'events { worker_connections 64; }',
      body,
    ].join("\n"))
  end

  # Starts nginx and waits until it listens on the http ports and the master
  # runs all its workers. The block runs after the prefix is made.
  def start(generation = 1)
    (@spec[:http] + @spec[:stream]).each do |port|
      raise "port #{port} is already in use" if port_open?(port)
    end
    FileUtils.rm_rf(@prefix)
    FileUtils.mkdir_p(@prefix)
    [@error_log, @stderr_log].each { |f| File.write(f, '') }
    yield if block_given?
    write_conf(generation)
    runner = ENV['NGINX_RUNNER'].to_s.split
    runner = [] if runner == ['exec']
    @pid = Process.spawn(*runner, File.join(@install, 'sbin', 'nginx'),
                         '-p', @prefix, '-c', @conf, '-e', @error_log,
                         out: [@stderr_log, 'a'], err: [@stderr_log, 'a'])
    # Only the http ports are probed: a connection to a stream port runs the
    # session code of its server.
    wait_until("nginx (pid #{@pid}) to listen on #{@spec[:http].join(', ')}") do
      check_running
      @spec[:http].all? { |port| port_open?(port) }
    end
    wait_until("the #{@spec[:workers]} workers of nginx (pid #{@pid})") do
      check_running
      workers.size == @spec[:workers]
    end
    workers
  end

  def check_running
    return unless Process.waitpid(@pid, Process::WNOHANG)

    @status = $?
    raise "nginx #{describe(@status)}; see #{@error_log} and #{@stderr_log}"
  end

  def describe(status)
    status.signaled? ? "ended by signal #{status.termsig}" : "exited #{status.exitstatus}"
  end

  # The workers that the master runs now, sorted. Each is added to @seen.
  def workers
    pids = processes.select { |_, p| p[:ppid] == @pid && !p[:stat].start_with?('Z') }.keys.sort
    @seen |= pids
    pids
  end

  def pid_file
    File.read(prefix_path('nginx.pid')).strip.to_i
  end

  def reload(generation)
    write_conf(generation)
    Process.kill(:HUP, pid_file)
  end

  def log
    File.exist?(@error_log) ? File.read(@error_log).split("\n") : []
  end

  # The pid of the process that wrote a line of the error log.
  def self.line_pid(line)
    m = line.match(/\] (\d+)#\d+: /)
    m && m[1].to_i
  end

  # A worker counts as running while its pid runs a process whose command
  # line names nginx ("nginx: worker process", or the path of sbin/nginx
  # under valgrind) and that has not ended.
  def alive?(pid)
    p = processes[pid]
    !p.nil? && !p[:stat].start_with?('Z') && p[:args].include?('nginx')
  end

  # Sends SIGTERM to the master that the pid file names and waits until it
  # and every worker that it ran have ended. The master sends its workers the
  # command to terminate and collects them before it exits. It waits for
  # signals with sigsuspend(), so a signal cannot arrive unseen, as it can
  # for a single process ("Stopping nginx" in docs/test/README.md). After
  # LIMIT seconds the master and the workers that still run get SIGKILL.
  def stop
    return "nginx had ended: #{describe(@status)}" if @status

    workers
    target = begin
      pid_file
    rescue StandardError
      @pid
    end
    # Signal only the process that this script started.
    target = @pid unless target == @pid
    Process.kill(:TERM, target)
    deadline = now + LIMIT
    loop do
      if Process.waitpid(@pid, Process::WNOHANG)
        @status = $?
        return "master #{describe(@status)}; #{workers_ended(deadline)} of #{@seen.size} workers ended"
      end
      if now > deadline
        ([@pid] + @seen).each { |p| Process.kill(:KILL, p) if alive?(p) }
        Process.waitpid(@pid)
        return "killed after #{LIMIT} seconds"
      end
      sleep 0.05
    end
  rescue Errno::ESRCH, Errno::ECHILD
    'gone before SIGTERM'
  end

  def workers_ended(deadline)
    loop do
      left = @seen.select { |p| alive?(p) }
      return @seen.size if left.empty?

      if now > deadline
        left.each { |p| Process.kill(:KILL, p) }
        return @seen.size - left.size
      end
      sleep 0.05
    end
  end

  def collect
    errors = log.grep(ERROR_LEVEL)
    out 'error_lines', errors.size
    out 'error_line', errors.first unless errors.empty?
    [@error_log, @stderr_log].each do |path|
      next unless File.exist?(path)

      line = File.read(path).split("\n").find { |l| l =~ SANITIZER }
      next unless line

      out 'sanitizer', "#{File.basename(path)}: #{line.strip}"
      break
    end
    valgrind_summaries
  end

  def valgrind_summaries
    m = ENV['NGINX_RUNNER'].to_s.match(/--log-file=(\S*%p\S*)/)
    return unless m && @pid

    ([@pid] + @seen).each do |p|
      path = m[1].gsub('%p', p.to_s)
      line = File.exist?(path) ? File.read(path).split("\n").grep(/== ERROR SUMMARY: /).last : nil
      out 'valgrind', line ? "#{p}:#{line[/ERROR SUMMARY: (\d+) errors/, 1]}" : "#{p}:no summary"
    end
  end
end

def run_isolation(nginx)
  port = MODES['isolation'][:http][0]
  out 'workers', nginx.start.join(',')
  out 'master', nginx.pid
  out 'pid_file', nginx.pid_file
  answers = Hash.new(0)
  requests = 0
  while (answers.size < MODES['isolation'][:workers] || answers.values.min < 2) && requests < 200
    response = get(port, '/worker')
    out 'response', response
    answers[response[/pid=(\d+)/, 1]] += 1
    requests += 1
  end
  out 'requests', requests
end

# The index of the first line of the error log that includes text and was
# written by pid; nil when there is none.
def log_index(lines, pid, text)
  lines.index { |l| l.include?(text) && WorkersNginx.line_pid(l) == pid }
end

def order(nginx, pid, resumed)
  lines = nginx.log
  shutdown = log_index(lines, pid, 'gracefully shutting down')
  back = log_index(lines, pid, resumed)
  return 'shutdown missing' unless shutdown
  return 'resumed missing' unless back

  shutdown < back ? 'shutdown,resumed' : 'resumed,shutdown'
end

def write_script(nginx, generation)
  File.write(nginx.prefix_path('script.rb'), "Nginx.rputs \"script generation #{generation}\"\n")
end

def run_reload(nginx)
  http = MODES['reload'][:http][0]
  stream = MODES['reload'][:stream][0]
  old = nginx.start(1) { write_script(nginx, 1) }
  out 'workers', old.join(',')
  out 'master', nginx.pid
  out 'pid_file', nginx.pid_file
  out 'before', get(http, '/generation')
  out 'script_before', get(http, '/script')

  started = lambda do |what|
    wait_until("the #{what} sleep to start") do
      line = nginx.log.find { |l| l.include?("workers reload: #{what} sleep started") }
      line && WorkersNginx.line_pid(line)
    end
  end
  http_thread = Thread.new { get(http, '/sleep') }
  http_worker = started.call('http')
  stream_thread = Thread.new { exchange(stream) }
  stream_worker = started.call('stream')
  out 'http_sleep_worker', http_worker
  out 'stream_sleep_worker', stream_worker

  write_script(nginx, 2)
  nginx.reload(2)
  out 'after', wait_until('generation 2 to answer') {
    response = get(http, '/generation')
    response if response.include?('generation 2')
  }
  out 'script_after', get(http, '/script')
  wait_until('every old worker to shut down') do
    lines = nginx.log
    old.all? { |p| log_index(lines, p, 'gracefully shutting down') }
  end
  out 'in_flight', [http_thread.alive? ? 'http' : nil, stream_thread.alive? ? 'stream' : nil].compact.join(',')
  out 'old_alive', old.select { |p| nginx.alive?(p) }.join(',')

  FileUtils.touch(nginx.prefix_path('release'))
  [[http_thread, 'http_in_flight'], [stream_thread, 'stream_in_flight']].each do |thread, key|
    raise "#{key}: no answer within #{LIMIT} seconds" unless thread.join(LIMIT)

    out key, thread.value
  end
  out 'http_order', order(nginx, http_worker, 'workers reload: http sleep resumed')
  out 'stream_order', order(nginx, stream_worker, 'workers reload: stream sleep resumed')
  deadline = now + LIMIT
  sleep 0.05 while old.any? { |p| nginx.alive?(p) } && now < deadline
  out 'old_ended', "#{old.count { |p| !nginx.alive?(p) }} of #{old.size}"
  out 'new_workers', (nginx.workers - old).join(',')
  out 'after_release', get(http, '/generation')
  out 'stream_after', exchange(stream)
end

mode = ARGV[0]
unless MODES.key?(mode)
  out 'error', "unknown mode #{mode.inspect}"
  exit 1
end

started_at = now
nginx = WorkersNginx.new(mode)
begin
  mode == 'isolation' ? run_isolation(nginx) : run_reload(nginx)
rescue StandardError => e
  out 'error', "#{e.class}: #{e.message}"
ensure
  out 'exit', nginx.stop if nginx.pid
  nginx.collect
  out 'seconds', format('%.2f', now - started_at)
end
