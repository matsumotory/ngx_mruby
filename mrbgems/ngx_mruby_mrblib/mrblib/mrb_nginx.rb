class Nginx
  class Request
    def scheme
      self.var.scheme
    end

    def document_root
      Nginx::Server.new.document_root
    end

    def read_body
      # NOP. Just for backward compatibility.
      Nginx::OK
    end

    def body
      self.get_body
    end

    def uri_args
      args_to_hash(self.args)
    end

    def uri_args=(params)
      raise ArgumentError unless params.is_a?(Hash)
      self.args = params.map{|k,v| "#{k}=#{v}"}.join("&")
    end

    def post_args
      args_to_hash(self.body)
    end

    private

    def args_to_hash(args)
      Hash[*args.split("&").map{|arg| arg.split("=", 2)}.flatten]
    end
  end

  class Headers_in
    def user_agent
      self["User-Agent"]
    end
  end

  def self.var
    Var.new
  end

  class Utils
    class << self
      def encode_parameters(params, delimiter = '&', quote = nil)
        if params.is_a?(Hash)
          params = params.map do |key, value|
            sprintf("%s=%s%s%s", escape(key), quote, escape(value), quote)
          end
        else
          params = params.map { |value| escape(value) }
        end
        delimiter ? params.join(delimiter) : params
      end

      def escape(str)
        reserved_str = [
          "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "n", "m", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
          "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
          "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
          "-", ".", "_", "~"
        ]
        tmp = ''
        str = str.to_s
        str.size.times do |idx|
          chr = str[idx]
          if reserved_str.include?(chr)
            tmp += chr
          else
            tmp += "%" + chr.unpack("H*").first.upcase
          end
        end
        tmp
      end
    end
  end

  class Stream
    class Async
      class << self
        def sleep(*args)
          __sleep(*args)
          Fiber.yield
        end
      end
    end
  end

  class Async
    class << self
      def sleep(*args)
        __sleep(*args)
        Fiber.yield
      end
    end

    class HTTP
      class << self
        def sub_request(location, query_param = nil)
          if query_param.is_a?(Hash)
            __sub_request(location, ::Nginx::Utils.encode_parameters(query_param))
          elsif query_param.is_a?(String)
            __sub_request(location, query_param)
          else
            __sub_request(location)
          end
          Fiber.yield
        end
      end

      class Response
        attr_reader :body, :headers, :status
      end
    end
  end
end


module Kernel
  def get_server_class
    Nginx
  end

  def _ngx_mrb_prepare_fiber(nginx_handler)
    fiber_handler = Fiber.new { nginx_handler.call }

    lambda do
      # BUG?: return nginx_handler directly from fiber, not proc in any case.
      result = fiber_handler.resume
      [fiber_handler.alive?, result]
    end
  end
end
