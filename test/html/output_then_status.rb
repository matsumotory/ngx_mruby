# Hook script of test/conf/conf.d/68-output-then-status.conf (port 18154), for
# test/t/cases/output_then_status.rb. The path of the request names what the
# content handler does: it writes output with Nginx.rputs or Nginx.echo and
# sets a status with Nginx.return, Nginx.send_header or Nginx.status_code=,
# in the order of the lines below.
case Nginx::Request.new.uri
when '/accepted'
  Nginx.rputs 'accepted'
  Nginx.return Nginx::HTTP_ACCEPTED
when '/echo_then_status_code_203'
  Nginx.echo 'non-authoritative'
  Nginx.status_code = 203
when '/send_header_partial_content'
  Nginx.rputs 'partial'
  Nginx.send_header Nginx::HTTP_PARTIAL_CONTENT
when '/continue'
  Nginx.rputs 'continue'
  Nginx.return Nginx::HTTP_CONTINUE
when '/zero'
  Nginx.rputs 'zero'
  Nginx.return 0
when '/ok'
  Nginx.rputs 'ok'
  Nginx.return Nginx::HTTP_OK
when '/created'
  Nginx.rputs 'created'
  Nginx.return Nginx::HTTP_CREATED
when '/not_found'
  Nginx.rputs 'not found'
  Nginx.return Nginx::HTTP_NOT_FOUND
when '/status_before_output'
  Nginx.return Nginx::HTTP_ACCEPTED
  Nginx.rputs 'status first'
end
