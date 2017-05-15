class Nginx
  class SSL
    class ACME
      class Client
        def initialize(end_point, domain, allow_domains=[], redis)
          @end_point = end_point
          @domain = domain
          @allow_domains = allow_domains
          @redis = redis
        end

        def allow_domain?
          @allow_domains.include? @domain
        end

        def client
          Acme::Client.new(
            private_key,
            @end_point,
            { request: { open_timeout: 5, timeout: 5 } }
          )
        end

        def private_key
          unless @_private_key
            @_private_key = if raw = @redis.get("#{@domain}_private_key")
              OpenSSL::PKey::RSA.new(raw)
            else
              OpenSSL::PKey::RSA.new(2048)
            end
          end
          @_private_key
        end

        def register
          registration = client.register("mailto:admin@#{@domain}")
          if registration.agree_terms
            @redis.set("#{@domain}_private_key", private_key.to_pem.to_s)
          end
        end

        def clear
          @redis.del("#{@domain}_token_value")
          @redis.del("#{@domain}_authorization_uri")
        end

        def auto_cert_deploy
          unless @redis.get("#{@domain}_token_value")
            raise "Client registration failed" unless register
            authorization = client.authorize(@domain)
            challenge = authorization.http01
            challenge = client.fetch_authorization(authorization.uri).http01
            challenge.request_verification

            @redis.set("#{@domain}_token_value", challenge.file_content.to_s)
            @redis.set("#{@domain}_authorization_uri", authorization.uri)
            return nil
          end

          if uri = @redis.get("#{@domain}_authorization_uri")
            challenge = client.fetch_authorization(uri).http01
            Nginx::SSL.log ::Nginx::LOG_ERR,  challenge.authorization.verify_status
            if challenge.authorization.verify_status == "valid"
              csr = Acme::Client::CertificateRequest.new([@domain])
              begin
                certificate = client.new_certificate(csr)
              rescue => e
                Nginx::SSL.log ::Nginx::LOG_ERR, e.message
                clear
              end

              @redis.set("#{@domain}.crt", certificate.fullchain_to_pem)
              @redis.set("#{@domain}.key", certificate.request.private_key.to_pem)
            end
          end
        end
      end
    end
  end
end
