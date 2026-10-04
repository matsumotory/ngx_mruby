# Body filter hook for /filter/output_file in
# test/conf/conf.d/20-filter-connection.conf.
f = Nginx::Filter.new
f.output "file: #{f.body}"
