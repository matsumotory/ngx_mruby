module Kernel
  module Rack
    Server = get_server_class

    class Logger
      def fatal(message = nil, &block)
        add Server::LOG_EMERG, message, &block
      end
      def error(message = nil, &block)
        add Server::LOG_ERR, message, &block
      end
      def warn(message = nil, &block)
        add Server::LOG_WARN, message, &block
      end
      def info(message = nil, &block)
        add Server::LOG_INFO, message, &block
      end
      def debug(message = nil, &block)
        add Server::LOG_DEBUG, message, &block
      end

      # apache httpd/nginx specific 
      def emerg(message = nil, &block)
        add Server::LOG_EMERG, message, &block
      end
      def alert(message = nil, &block)
        add Server::LOG_ALERT, message, &block
      end
      def crit(message = nil, &block) 
        add Server::LOG_CRIT, message, &block
      end
      def notice(message = nil, &block) 
        add Server::LOG_NOTICE, message, &block
      end

      private

      def add(severity, message = nil)
        message = yield if message.nil? && block_given?
        Server.log severity, message
      end

    end

    class LazyStringIO
      # Avoid naming conflicts with Kernel methods introduced by mruby-io
      undef_method :gets, :getc

      def initialize(proc)
        @proc = proc
        @stringio = nil
      end
      def method_missing(sym, *args, &block)
        @stringio = StringIO.new(@proc.call) if @stringio.nil?
        @stringio.send sym, *args, &block
      end
    end

    def self.build_env r, c
      input = (r.method == "POST" || r.method == "PUT") ? lambda {r.body} : lambda {""}
      env = {
        "REQUEST_METHOD"    => r.method,
        "SCRIPT_NAME"       => "",
        "PATH_INFO"         => r.uri,
        "REQUEST_URI"       => r.unparsed_uri,
        "QUERY_STRING"      => r.args,
        "SERVER_NAME"       => r.hostname,
        "SERVER_ADDR"       => c.local_ip,
        "SERVER_PORT"       => c.local_port.to_s,
        "REMOTE_ADDR"       => c.remote_ip,
        "REMOTE_PORT"       => c.remote_port.to_s,
        "rack.url_scheme"   => r.scheme,
        "rack.multithread"  => false,
        "rack.multiprocess" => true,
        "rack.run_once"     => false,
        "rack.hijack?"      => false,
        "rack.logger"       => Logger.new,
        "rack.input"       => LazyStringIO.new(input),
        "server.name"       => server_name,
        "server.version"    => Server.server_version,
      }

      # add rquest headers into env
      r.headers_in.all.each do |k, v|
        k = k.upcase.gsub('-', '_')
        env["HTTP_#{k}"] = v 
        # Rack spec doesn't allow env contains HTTP_CONTENT_TYPE or HTTP_CONTENT_LENGTH,
        # but don't want to break backward compatibility.
        env[k] = v if k == 'CONTENT_TYPE' || k == 'CONTENT_LENGTH'
      end

      env
    end

    def self.build_response r, res
      return if res.nil?

      if res[1].kind_of?(Hash)
        res[1].each { |k, v| r.headers_out[k] = v }
      elsif res[1].kind_of?(Array)
        res[1].each { |ary| 
          raise TypeError, "response headers arg type must be Array of Array or Hash" unless ary.kind_of?(Array)
          r.headers_out[ary[0]] = ary[1] 
        }
      else
        raise TypeError, "response headers arg type must be Array of Array or Hash"
      end
      if res[2].kind_of?(Array)
        res[2].each { |b| Server.rputs b.to_s }
      else
        raise TypeError, "response body arg type must be Array"
      end
      Server.return res[0].to_i if res[0]
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
