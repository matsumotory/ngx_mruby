# Shared prelude for test/t/cases/*.rb. test.sh concatenates this file in
# front of each case before running it with the test build of mruby.

def http_host(port = 58080)
  "127.0.0.1:#{port}"
end

def base(port = 58080)
  "http://#{http_host(port)}"
end

def base_ssl(port)
  "https://localhost:#{port}"
end
