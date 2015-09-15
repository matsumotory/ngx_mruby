module Kernel
  module Rack
    Server = get_server_class

    def self.build_env r, c
      env = {}
      env = {
        "REQUEST_METHOD" => r.method,
        "SCRIPT_NAME" => "",
        "PATH_INFO" => r.uri,
        "REQUEST_URI" => r.unparsed_uri,
        "QUERY_STRING" => r.args,
        "SERVER_NAME" => r.hostname,
        "SERVER_ADDR" => c.local_ip,
        "SERVER_PORT" => c.local_port.to_s,
        "REMOTE_ADDR" => c.remote_ip,
        "REMOTE_PORT" => c.remote_port.to_s,
        "rack.url_scheme" => r.var.scheme,
        "rack.multithread" => false,
        "rack.multiprocess" => true,
        "rack.run_once" => false,
        "rack.hijack?" => false,
        "server.name" => server_name,
        "server.version" => Server.server_version,
      }

      # add rquest headers into env
      r.headers_in.all.keys.each do |k|
        env["HTTP_#{k.upcase.gsub('-', '_')}"] = r.headers_in[k]
      end

      env
    end
    def self.build_response r, res
      if res[1].kind_of?(Hash)
        res[1].keys.each { |k| r.headers_out[k] = res[1][k] }
      elsif res[1].kind_of?(Array)
        res[1].each { |ary| r.headers_out[ary[0]] = ary[1] }
      else
        raise TypeError, "response headers arg type must be Array or Hash"
      end
      if res[2].kind_of?(Array)
        res[2].each { |b| Server.rputs b.to_s }
      else
        raise TypeError, "response body arg type must be Array"
      end
      Server.return res[0].to_i
    end
  end
  def run obj
    Server = get_server_class
    r = Server::Request.new
    c = Server::Connection.new

    env = Kernel::Rack.build_env r, c
    res = obj.call env
    Kernel::Rack.build_response r, res
  end
end
