# Hook script of test/conf/conf.d/74-headers-exact.conf (port 18095), for
# test/t/cases/headers_exact.rb. Each path calls Nginx::Headers_in or
# Nginx::Headers_out and answers with what the headers hold afterwards.

# A value whose to_s returns a String.
class HeadersExactValue
  def to_s
    "from-to-s"
  end
end

# A value whose to_s raises.
class HeadersExactBadValue
  def to_s
    raise "headers-exact-to-s"
  end
end

r = Nginx::Request.new
hin = r.headers_in
hout = r.headers_out
case r.uri
when '/in_delete'
  # The request has X-Foo: 1, X-Foo-Bar: 2 and X-Foo: 3. delete removes both
  # X-Foo and leaves X-Foo-Bar, whose name only starts with X-Foo.
  hin.delete 'X-Foo'
  Nginx.rputs "X-Foo=#{hin['X-Foo'].inspect} X-Foo-Bar=#{hin['X-Foo-Bar'].inspect}"
when '/in_delete_symbol'
  # The same with a Symbol in other case.
  hin.delete :'x-foo'
  Nginx.rputs "X-Foo=#{hin['X-Foo'].inspect} X-Foo-Bar=#{hin['X-Foo-Bar'].inspect}"
when '/in_set'
  # []= replaces both X-Foo and leaves X-Foo-Bar.
  hin['X-Foo'] = 'new'
  Nginx.rputs "X-Foo=#{hin['X-Foo'].inspect} X-Foo-Bar=#{hin['X-Foo-Bar'].inspect}"
when '/out_delete'
  # Two X-D headers, deleted by a name in other case: the response has none.
  hout['X-D'] = %w[a b]
  hout.delete 'x-d'
  hout['X-Kept'] = 'kept'
  Nginx.rputs "X-D=#{hout['X-D'].inspect}"
when '/content_type'
  # Content-Type goes to nginx's own field, which [] reads back.
  hout['Content-Type'] = 'application/json'
  Nginx.rputs "Content-Type=#{hout['Content-Type'].inspect}"
when '/content_type_delete'
  hout['Content-Type'] = 'application/json'
  hout.delete 'Content-Type'
  Nginx.rputs "Content-Type=#{hout['Content-Type'].inspect}"
when '/date'
  # The response has this Date only, not nginx's own as well.
  hout['Date'] = 'Thu, 01 Jan 2026 00:00:00 GMT'
  Nginx.rputs "Date=#{hout['Date'].inspect}"
when '/location_relative'
  # A Location that starts with "/" is made absolute by nginx
  # (absolute_redirect, on by default), as for nginx's own redirects.
  hout['Location'] = '/headers-exact-target'
  Nginx.return Nginx::HTTP_MOVED_TEMPORARILY
when '/location_absolute'
  hout['Location'] = 'http://example.com/headers-exact-target'
  Nginx.return Nginx::HTTP_MOVED_TEMPORARILY
when '/server_lower'
  # A name in lower case still names nginx's Server: one Server line.
  hout['server'] = 'headers-exact'
  Nginx.rputs "Server=#{hout['Server'].inspect}"
when '/server_delete'
  # Deleting the Server that the script set gives nginx's own back.
  hout['Server'] = 'headers-exact'
  hout.delete 'Server'
  Nginx.rputs "Server=#{hout['Server'].inspect}"
when '/value_to_s'
  # A value that is not a String is converted with to_s; a Symbol names a
  # header; an Array adds one header per element.
  hout['X-N'] = 1
  hout['X-Object'] = HeadersExactValue.new
  hout[:'X-Sym-Name'] = :sym_value
  hout['X-Arr'] = ['a', 2]
  hin[:'X-In-Sym'] = 3
  Nginx.rputs "X-In-Sym=#{hin['X-In-Sym'].inspect} X-Arr=#{hout[:'X-Arr'].inspect}"
when '/value_to_s_raises'
  # A to_s that raises: []= raises it and leaves the header as it was.
  hout['X-Partial'] = 'old'
  begin
    hout['X-Partial'] = ['new', HeadersExactBadValue.new]
    Nginx.rputs 'not raised'
  rescue => e
    Nginx.rputs "#{e.class}: #{e.message} X-Partial=#{hout['X-Partial'].inspect}"
  end
when '/name_types'
  # A name that is neither a String nor a Symbol raises TypeError in []=,
  # [] and delete.
  out = []
  [-> { hout[1] = 'x' }, -> { hin[nil] = 'x' }, -> { hout.delete 1.5 }, -> { hin.delete [] }, -> { hout[2] }].each do |call|
    begin
      call.call
      out << 'ok'
    rescue TypeError
      out << 'TypeError'
    end
  end
  Nginx.rputs out.join(',')
else
  Nginx.return Nginx::HTTP_NOT_FOUND
end
