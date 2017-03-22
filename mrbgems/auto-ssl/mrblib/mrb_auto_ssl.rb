class Nginx
  class SSL
    class ACME
      class << self
        def token_filename_from_url r
          if r.uri =~ /\/([A-Za-z0-9\\-_]+)$/
            token_filename = $1
          end
          Nginx.log Nginx::LOG_ERR, "ACME chanllenge .omain:#{r.hostname} filename:#{token_filename}"
          token_filename
        end

        def secret_token r
          r.headers_in["X-Hook-Secret"]
        end

        def challenged_domain r
          r.post_args["domain"]
        end

        def challenged_token_filename r
          r.post_args["token_filename"]
        end

        def challenged_token_value r
          r.post_args["token_value"]
        end

        def deploy_cert_information r
          key_path = r.post_args["privkey"]
          crt_path = r.post_args["fullchain"]

          raise "not found key file: #{key_path}" unless File.exists? key_path
          raise "not found crt file: #{crt_path}" unless File.exists? crt_path

          {domain: r.post_args["domain"], key: File.open(key_path).read, crt: File.open(crt_path).read}
        end
      end

      def initialize(domain, dehydrated_opts, allow_domains=[])
        @domain = domain
        @dehydrated = dehydrated_opts
        @allow_domains = allow_domains
      end

      def allow_domain?
        @allow_domains.include? @domain
      end

      def auto_accept_terms
        command = [@dehydrated[:bin],
                    "--register",
                    "--accept-terms",
                    "--config #{@dehydrated[:conf]}",
                  ].join(" ")
        res = `#{command}`
        Nginx::SSL.log Nginx::LOG_INFO, res
      end

      def auto_cert_deploy
        license_info_str = "To use dehydrated with this certificate authority you have to agree to their terms of service which you can find here"
        command = [@dehydrated[:bin],
                      "--cron",
                      "--no-lock",
                      "--domain #{@domain}",
                      "--challenge http-01",
                      "--hook #{@dehydrated[:hook]}",
                      "--config #{@dehydrated[:conf]}",
                  ].join(" ")

        res = `HOOK_SECRET=#{@dehydrated[:secret_token]} #{command}`
        Nginx::SSL.log Nginx::LOG_INFO, res

        if /#{license_info_str}/ === res
          auto_accept_terms
          auto_cert_deploy
        end
      end
    end
  end
end
