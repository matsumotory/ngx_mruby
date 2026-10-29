# Trust boundary

ngx_mruby runs Ruby code that the operator of the nginx server writes, and it treats what a client sends as input to that code. It is not a sandbox: it does not confine the code that the configuration loads. This page says what each side of the boundary is, what ngx_mruby is responsible for, what the operator's code is responsible for, and how this maps onto the scope of [SECURITY.md](../../SECURITY.md).

## The trusted side: the configuration and the code it loads

- The nginx configuration and all the Ruby code that it loads are trusted: the script files that the directives name (`mruby_content_handler /path/to/handler.rb` and the others), the inline code of the `*_code` directives, and the gems that `build_config.rb` builds into the module. ngx_mruby compiles and runs this code as it is, and does not check what the code does.
- With [`mruby_add_handler on`](../directives/README.md#mruby_add_handler), the request URI chooses which file runs: ngx_mruby maps the URI to a path under the location's root and runs that file as a content handler. Every file that the location matches under that root is code of this kind.
- The init code (`mruby_init`, `mruby_init_code`, `mruby_stream_init`, `mruby_stream_init_code`) and the server configuration code (`mruby_server_context_handler_code`, `mruby_stream_server_context_code`) run in the master process while nginx reads the configuration, with the privileges that nginx was started with (root, when nginx is started as root). All the other code (init_worker and exit_worker code, every handler and filter, the SSL handshake handlers, the stream handlers) runs in the worker processes, with the privileges of the workers (the user of the `user` directive, when the master runs as root).
- All the code of an `http {}` block runs in one `mrb_state` per worker (and one for the `stream {}` block), shared by every server, location and client of that block ([What a worker keeps between requests](../concepts/lifetimes.md#what-a-worker-keeps-between-requests)). The code of one location can read and change the global variables, constants, classes and methods that the code of another server or location defined. ngx_mruby does not separate the scripts of one block from each other.
- The default build gives this code the mruby core gems that `NGX_MRUBY_CORE_GEMS` in `build_config.rb` lists ([Core gems](../install/README.md#core-gems)) and the other gems of `build_config.rb`. Among them are `eval` and `instance_eval` (mruby-eval), files, `IO.popen` and backquotes, which run shell commands (mruby-io), sockets (mruby-socket), `sleep` (mruby-sleep), `Process` (iij/mruby-process), `ENV` and `Dir`. A script can do what the user of its process can do.

Whoever can change the nginx configuration, a script that it loads, a directory that holds such a script, or `build_config.rb` can therefore run any code as the workers, and through the init code as the master. A setup that takes nginx configuration or Ruby code from parties that the operator does not trust, such as a multi-tenant service that runs a snippet per customer, gives each of those parties that power over the whole nginx and every other party's traffic. ngx_mruby has no means to confine such code, and does not support this use.

## The untrusted side: what a client sends

Everything that a client sends is untrusted input: the request line, the URI and its arguments, the headers and cookies, the request body, and the values that nginx derives from them. Scripts read these values through [`Nginx::Request`](../class_and_method/README.md#nginxrequest-class) (`uri`, `unparsed_uri`, `args`, `uri_args`, `post_args`, `method`, `headers_in`, `get_body`, `user` and the others), [`Nginx::Headers_in`](../class_and_method/README.md#nginxheaders_in-class), and [`Nginx::Var`](../class_and_method/README.md#nginxvar-class) (for example `$http_*`, `$arg_*`, `$cookie_*` and `$request_uri`). The server name that a client sends in the TLS handshake ([`Nginx::SSL#servername`](../class_and_method/README.md#nginxsslservername---string)) is untrusted in the same way. A response from an upstream server, also one that a subrequest or an output filter reads, is as trustworthy as that upstream server.

## What ngx_mruby is responsible for

- nginx parses the request before ngx_mruby sees it. The C code of ngx_mruby (`src/`) and its bundled gems (`mrbgems/`) hand the request's values to the script as Ruby strings and other objects, and take the values that the script passes back as data. A configuration that uses the directives and methods as they are documented is not meant to make ngx_mruby read or write memory outside its buffers, end or hang the worker, or give one request the data of another, whatever the client sends and also when the script passes client input on to a method of ngx_mruby. Where it does, that is a defect of ngx_mruby, also when the script's own call, and no client value, triggers it.
- 2.7.1 and 2.7.2 fixed defects of this kind in calls that the configuration's own code makes; in some of them a client value had no part. In 2.7.0 a body filter that made a body written with `Nginx.rputs` or `Nginx.echo` shorter sent bytes from beyond the end of the new body, and request-scoped methods called outside a request could use the data of another request ([2.7.1 release notes](../releases/v2.7.1.md), entries 2 and 8, and the advisory [GHSA-h7fw-wf49-8rv5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-h7fw-wf49-8rv5)). In 2.7.1 `Nginx::Var` read memory outside the name or the arguments for an empty name, a name made only of `=`, and a setter without its value, and `Nginx::Var#set` changed the String or Symbol passed as the name ([2.7.2 release notes](../releases/v2.7.2.md), entries 1 and 2). The accessor now checks the name and the arguments before it reads them, and `#set` looks the variable up by a lowercased copy of the name, whatever value the script passes, also one that it took from the client.

## What the operator's code is responsible for

ngx_mruby runs what the script asks for. What follows from passing client input on is the script's responsibility.

- Validate client input before it reaches anything that acts on it: `eval` or `instance_eval`, a shell command (backquotes, `IO.popen`, `Process`), a file path (`File`, `Dir`, [`Nginx::SSL#certificate=`](../class_and_method/README.md#nginxsslcertificatestring) and `#certificate_key=`), the name of an nginx variable (`Nginx::Var` with a name built at run time, `Nginx::Var#set`), an upstream address (`mruby_set $backend`, `Nginx::Upstream#server=`), a redirect target or a response header. Compare the input with a list of allowed values, or parse it into the type that the code expects, and reject what does not match. For example, a handshake handler that builds the path of a certificate from the server name lets the client choose the path; look the name up in a table instead, so that only names with a certificate reach a path:

  ```nginx
  http {
      mruby_init_code '
          CERT_DIRS = {
            "example.com"     => "/etc/nginx/certs/example.com",
            "www.example.com" => "/etc/nginx/certs/www.example.com",
          }
      ';

      server {
          listen 443 ssl;
          ssl_certificate     /etc/nginx/certs/default.crt;
          ssl_certificate_key /etc/nginx/certs/default.key;

          mruby_ssl_handshake_handler_code '
              ssl = Nginx::SSL.new
              dir = CERT_DIRS[ssl.servername]
              if dir
                ssl.certificate = "#{dir}/cert.pem"
                ssl.certificate_key = "#{dir}/key.pem"
              end
          ';
      }
  }
  ```

  A handshake whose code sets no certificate uses the server's `ssl_certificate` and `ssl_certificate_key` ([Nginx::SSL](../class_and_method/README.md#nginxssl-class)). `certificate=` and `certificate_key=` make the worker read the files during the handshake, which blocks it (see the next item). To avoid the read, load the PEM data in the init code and set it with [`certificate_data=`](../class_and_method/README.md#nginxsslcertificate_datastring) and [`certificate_key_data=`](../class_and_method/README.md#nginxsslcertificate_key_datastring).
- Keep the data of one request out of global variables, constants, instance variables of `main` and `Userdata`: the next request of the worker, from any client, sees it ([What a worker keeps between requests](../concepts/lifetimes.md#what-a-worker-keeps-between-requests)).
- Avoid blocking calls on the request path. A worker serves many clients at once, and while a script waits in `sleep`, a socket, a file, a shell command, `Process` or a Redis call, the worker serves no other client. A client that can make a script wait can therefore slow down every client of that worker. Use [`Nginx::Async.sleep`](../class_and_method/README.md#nginxasyncsleepmsec) and [`Nginx::Async::HTTP.sub_request`](../class_and_method/README.md#nginxasynchttpsub_requestlocation-string_or_hashnil) where their documentation says that they work, and add `cache` to the script directives, set `mruby_cache on`, or use inline code, so that a script file is not read from disk on every request.
- Keep the nginx configuration, the scripts, the directories that hold them and `build_config.rb` writable only by the operator. With `mruby_add_handler on`, keep only handler scripts under that root, and do not store files that clients upload there.

## How this maps onto SECURITY.md

Report privately, as [SECURITY.md](../../SECURITY.md) describes, a defect of ngx_mruby (`src/`, `mrbgems/`) that makes ngx_mruby read or write memory outside its buffers, end or hang the worker, or reveal or change the data of another request, in a configuration that uses the directives and methods as they are documented, in particular when input a client controls triggers it. This includes a script that passes client input on to a method of ngx_mruby, and a documented call of the script that triggers the defect without any client value. Defects of bundled or third-party components go to their upstream projects as well, as SECURITY.md says. If you are not sure whether a defect is in scope, report it privately.

Outside the scope of SECURITY.md is what follows from the trusted side doing what it was written to do: a script that passes client input to `eval`, a shell command, a file path or another of the uses above; data of one request that a script keeps in a global and a later request sees; a blocking call in a script that stalls its worker; anyone who can change the configuration, a script or `build_config.rb` running code; and a setup that takes nginx configuration or Ruby code from parties that the operator does not trust.
