# Hook script of test/conf/conf.d/89-body-with-status.conf (port 18197), for
# test/t/cases/body_with_status.rb. The path of the request names what the
# handler does: it writes output with Nginx.rputs and then sets a status
# with Nginx.return, except on /status_only, which sets the status without
# output, and on the paths that start with /before_, which set the status
# before the output.
r = Nginx::Request.new
case r.uri
when '/content_401'
  r.content_type = 'application/json'
  r.headers_out['X-Reason'] = 'no key'
  Nginx.rputs '{"error":"no key"}'
  Nginx.return Nginx::HTTP_UNAUTHORIZED
when '/access_429'
  Nginx.rputs '{"error":"rate limited"}'
  Nginx.return Nginx::HTTP_TOO_MANY_REQUESTS
when '/access_202'
  Nginx.rputs 'accepted in access'
  Nginx.return Nginx::HTTP_ACCEPTED
when '/rewrite_403'
  Nginx.rputs '{"error":"rewrite"}'
  Nginx.return Nginx::HTTP_FORBIDDEN
when '/moved'
  Nginx.rputs 'moved without Location'
  Nginx.return Nginx::HTTP_MOVED_PERMANENTLY
when '/no_content'
  Nginx.rputs 'not sent with 204'
  Nginx.return Nginx::HTTP_NO_CONTENT
when '/not_modified'
  Nginx.rputs 'not sent with 304'
  Nginx.return Nginx::HTTP_NOT_MODIFIED
when '/switching_protocols'
  Nginx.rputs 'not sent with 101'
  Nginx.return Nginx::HTTP_SWITCHING_PROTOCOLS
when '/status_only'
  Nginx.return Nginx::HTTP_UNAUTHORIZED
when '/sub_target'
  Nginx.rputs 'sub forbidden'
  Nginx.return Nginx::HTTP_FORBIDDEN
when '/before_content_401'
  r.content_type = 'application/json'
  Nginx.status_code = Nginx::HTTP_UNAUTHORIZED
  Nginx.rputs '{"error":"status first"}'
when '/before_access_429'
  Nginx.return Nginx::HTTP_TOO_MANY_REQUESTS
  Nginx.rputs '{"error":"rate limited first"}'
when '/before_rewrite_403'
  Nginx.send_header Nginx::HTTP_FORBIDDEN
  Nginx.rputs '{"error":"forbidden first"}'
when '/before_access_200'
  Nginx.return Nginx::HTTP_OK
  Nginx.rputs 'ok in access'
when '/before_switching_protocols'
  Nginx.return Nginx::HTTP_SWITCHING_PROTOCOLS
  Nginx.rputs 'not sent with 101'
when '/before_then_after'
  Nginx.return Nginx::HTTP_UNAUTHORIZED
  Nginx.rputs 'the later status wins'
  Nginx.return Nginx::HTTP_FORBIDDEN
when '/before_sub_target'
  Nginx.status_code = Nginx::HTTP_ACCEPTED
  Nginx.rputs 'sub accepted'
when '/close_after_output', '/access_close_after_output'
  Nginx.rputs 'not sent before 444'
  Nginx.return Nginx::HTTP_CLOSE
when '/before_close'
  Nginx.return Nginx::HTTP_CLOSE
  Nginx.rputs 'not sent after 444'
end
