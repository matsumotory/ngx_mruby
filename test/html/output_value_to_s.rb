# Hook script of test/conf/conf.d/88-output-value-to-s.conf (port 18191), for
# test/t/cases/output_value_to_s.rb. It runs as the content handler of
# /content, the rewrite handler of /redirect and the body filter of /filter.
#
# The query names the call (rputs, echo, redirect, body or output) and the
# value: string ("http://example.com/string"), to_s_string (an object whose
# to_s returns "http://example.com/to_s"), no_to_s (a BasicObject, which has
# no to_s), to_s_raises (an object whose to_s raises) or to_s_not_string (an
# object whose to_s returns an Integer).
#
# The script rescues the exception of the call and shows it as
# "raised: CLASS: MESSAGE": in the body for rputs and echo (after "|"),
# in the response header X-Raised for redirect, and as the new body for body
# and output. With rescue=no, it lets the exception end the handler.
r = Nginx::Request.new
call = r.var.arg_call
rescue_it = r.var.arg_rescue != 'no'

value =
  case r.var.arg_value
  when 'string'
    'http://example.com/string'
  when 'to_s_string'
    o = Object.new
    def o.to_s
      'http://example.com/to_s'
    end
    o
  when 'no_to_s'
    BasicObject.new
  when 'to_s_raises'
    o = Object.new
    def o.to_s
      raise 'raised in to_s'
    end
    o
  when 'to_s_not_string'
    o = Object.new
    def o.to_s
      1
    end
    o
  else
    raise "no value for #{r.var.arg_value}"
  end

begin
  case call
  when 'rputs'
    Nginx.rputs value
    Nginx.rputs '|returned'
  when 'echo'
    Nginx.echo value
    Nginx.rputs '|returned'
  when 'redirect'
    Nginx.redirect value
  when 'body'
    Nginx::Filter.new.body = value
  when 'output'
    Nginx::Filter.new.output value
  else
    raise "no call for #{call}"
  end
rescue => e
  raise e unless rescue_it

  raised = "raised: #{e.class}: #{e.message}"
  case call
  when 'rputs', 'echo'
    Nginx.rputs "|#{raised}"
  when 'redirect'
    # A rewrite handler of 2.x that ends without a result ends the request
    # without a response, so the script declines to reach the content
    # handler of /redirect.
    r.headers_out['X-Raised'] = raised
    Nginx.return Nginx::DECLINED
  else
    Nginx::Filter.new.body = raised
  end
end
