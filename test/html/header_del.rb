# Hook script of test/conf/conf.d/73-header-del.conf (port 18105), for
# test/t/cases/header_del.rb. It deletes request headers and reports what the
# headers hold afterwards, so the case can see the result of
# ngx_mrb_del_request_header.
r = Nginx::Request.new
h = r.headers_in
case r.uri
when '/prefix'
  # "X-Prefix" is a prefix of the header "X-Prefix-Match". Before the fix the
  # shorter name matched and deleted the longer header.
  h.delete('X-Prefix')
  Nginx.rputs "match:#{h['X-Prefix-Match']}"
when '/empty-first'
  # X-A01..X-A20 fill the first part and X-A21 is in a second part. Deleting
  # X-A01..X-A20 empties the first part while the second part exists. Before
  # the fix the header added next was written into a detached part and could
  # not be read back.
  (1..20).each { |n| h.delete('X-A%02d' % n) }
  h['X-Last'] = 'last'
  Nginx.rputs "last:#{h['X-Last']}"
when '/overflow'
  # X-B01..X-B20 fill the first part. Deleting X-B19, from the middle, and
  # then adding headers made the previous code write past the end of the
  # part's array.
  h.delete('X-B19')
  (1..19).each { |n| h['X-N%02d' % n] = n.to_s }
  Nginx.rputs "overflow:#{h['X-N19']}"
when '/cache-ptr'
  # X-B sits before User-Agent, which is followed by X-C. $http_user_agent
  # reads r->headers_in.user_agent, the pointer nginx cached to the
  # User-Agent element while parsing. Deleting X-B (a middle element, the
  # split branch) must not move the other elements, or that pointer would
  # then point at a different header.
  h.delete('X-B')
  Nginx.rputs "ua:#{Nginx::Var.new.http_user_agent}"
when '/cache-ptr0'
  # X-First is at index 0 of the list; User-Agent follows it. Deleting the
  # first element (the i==0 branch, which advances the part's base) must not
  # move User-Agent, or $http_user_agent (r->headers_in.user_agent) would
  # read X-Last.
  h.delete('X-First')
  Nginx.rputs "ua:#{Nginx::Var.new.http_user_agent}"
else
  Nginx.return Nginx::HTTP_NOT_FOUND
end
