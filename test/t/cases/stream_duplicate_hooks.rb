# A stream hook given twice in one context: nginx -t refuses the second
# directive with "is duplicated", as it refuses a second HTTP directive for
# the same code (decision 4 of docs/proposals/core-alpha1.md). mruby_stream
# and mruby_stream_code are the same hook, and so are the file and the inline
# form of mruby_stream_init_worker and of mruby_stream_exit_worker
# (test/t/cases/stream.rb has mruby_stream_init). nginx_t and html_path are
# in test/t/cases/_prelude.rb. Port 12398 is only parsed: nginx -t listens on
# nothing.

t = SimpleTest.new "ngx_mruby test: stream hooks given twice"

STREAM_DUPLICATE_HOOKS_PORT = 12398

def stream_duplicate_hooks_conf(stream_body, server_body)
  [
    'stream {',
    stream_body,
    '    server {',
    "        listen 127.0.0.1:#{STREAM_DUPLICATE_HOOKS_PORT};",
    server_body,
    '        return "stream duplicate hooks";',
    '    }',
    '}',
  ].join("\n")
end

STREAM_HANDLER_FILE = "mruby_stream #{html_path('stream_lb.rb')};"
STREAM_HANDLER_CODE = %q{mruby_stream_code 'Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "stream duplicate hooks"';}

t.assert('stream duplicate hooks - nginx -t refuses mruby_stream_code after mruby_stream in one server', 'nginx -t') do
  out = nginx_t(stream_duplicate_hooks_conf('', "#{STREAM_HANDLER_FILE}\n#{STREAM_HANDLER_CODE}"))
  t.assert_include out, '"mruby_stream_code" directive is duplicated'
  t.assert_include out, 'test failed'
  t.assert_not_include out, 'test is successful'
end

t.assert('stream duplicate hooks - nginx -t refuses mruby_stream after mruby_stream_code in one server', 'nginx -t') do
  out = nginx_t(stream_duplicate_hooks_conf('', "#{STREAM_HANDLER_CODE}\n#{STREAM_HANDLER_FILE}"))
  t.assert_include out, '"mruby_stream" directive is duplicated'
  t.assert_include out, 'test failed'
  t.assert_not_include out, 'test is successful'
end

t.assert('stream duplicate hooks - nginx -t refuses a second mruby_stream_code in one server', 'nginx -t') do
  out = nginx_t(stream_duplicate_hooks_conf('', "#{STREAM_HANDLER_CODE}\n#{STREAM_HANDLER_CODE}"))
  t.assert_include out, '"mruby_stream_code" directive is duplicated'
  t.assert_include out, 'test failed'
end

t.assert('stream duplicate hooks - nginx -t refuses mruby_stream_code after mruby_stream in the stream block', 'nginx -t') do
  out = nginx_t(stream_duplicate_hooks_conf("#{STREAM_HANDLER_FILE}\n#{STREAM_HANDLER_CODE}", ''))
  t.assert_include out, '"mruby_stream_code" directive is duplicated'
  t.assert_include out, 'test failed'
end

{
  'mruby_stream_init_worker' => 'stream_init_worker.rb',
  'mruby_stream_exit_worker' => 'stream_exit_worker.rb',
}.each do |hook, file|
  t.assert("stream duplicate hooks - nginx -t refuses #{hook}_code after #{hook}", 'nginx -t') do
    out = nginx_t(stream_duplicate_hooks_conf("#{hook} #{html_path(file)};\n#{hook}_code 'true';", ''))
    t.assert_include out, "\"#{hook}_code\" directive is duplicated"
    t.assert_include out, 'test failed'
  end

  t.assert("stream duplicate hooks - nginx -t refuses #{hook} after #{hook}_code", 'nginx -t') do
    out = nginx_t(stream_duplicate_hooks_conf("#{hook}_code 'true';\n#{hook} #{html_path(file)};", ''))
    t.assert_include out, "\"#{hook}\" directive is duplicated"
    t.assert_include out, 'test failed'
  end
end

# One hook in each context is not a duplicate: the code of the server
# replaces that of the stream block for the server, as before.
t.assert('stream duplicate hooks - nginx -t accepts one handler in the stream block and one in a server', 'nginx -t') do
  out = nginx_t(stream_duplicate_hooks_conf(STREAM_HANDLER_CODE, STREAM_HANDLER_FILE))
  t.assert_include out, 'test is successful'
  t.assert_not_include out, 'is duplicated'
end

t.report
