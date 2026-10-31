# Migrating from ngx_mruby 2.x to 3.0.0

This guide is for moving scripts, configurations and builds from ngx_mruby
2.x to ngx_mruby 3.0.0. Each change that it covers is described once, under
[Behavior changes: read before upgrading](../releases/v3.0.0.md#behavior-changes-read-before-upgrading)
in the release notes of v3.0.0: what 2.x did, what 3.0.0 does, what is
affected and what to do. This guide links to each of those entries and adds
the steps and examples: how to find the scripts and builds that an entry
affects, what a change looks like in a script, and how to check the
result. Read the release notes of the 2.x releases newer than the version
you run first ([docs/releases](../releases/)).

ngx_mruby 2.x bundles mruby 3.3.0. The development line of ngx_mruby 3
bundles mruby 4.0.0, the current stable release of mruby. The v3 plan
(`docs/proposals/v3-plan.md`, section 7, decision 1) sets mruby 4.1.0 as
the target of v3, with 4.0.0 as an approved step before it; 4.1.0 has only
release candidates so far. The entries of mruby 4.0.0 are the changes that
were found and measured for ngx_mruby, not a complete list. mruby's own
lists of user-visible changes are `doc/mruby3.4.md` and `doc/mruby4.0.md`
in `mruby/`. mruby 4.1.0 brings further changes that the release notes and
this guide do not cover yet.

## Steps

1. Check how you build the module: [Builds](#builds).
2. Find the scripts that an entry affects, and change them: [Scripts](#scripts).
3. Update log parsers and alerts: [Log monitoring](#log-monitoring).
4. If you maintain an mrbgem or other C code that uses the mruby C API,
   check it: [C extensions and mrbgems](#c-extensions-and-mrbgems).
5. Check the result: [Checking the result](#checking-the-result).

## Builds

- With the `build_config.rb` of this release, rebuild the module; the
  bundled mruby is built with it
  ([The bundled mruby is 4.0.0 instead of 3.3.0](../releases/v3.0.0.md#the-bundled-mruby-is-400-instead-of-330-561)).
- With a `build_config.rb` of your own
  ([A `build_config.rb` of your own needs the core gem changes of mruby 4.0.0](../releases/v3.0.0.md#a-build_configrb-of-your-own-needs-the-core-gem-changes-of-mruby-400-561)),
  find the lines that select core gems:

  ```sh
  grep -nE 'gembox|mruby-print|hal-posix|mruby-task|mruby-encoding|mruby-sleep|ngx_mruby_core_gems' build_config.rb
  ```

  To keep the core gems that the default build of ngx_mruby takes, copy
  `NGX_MRUBY_CORE_GEMS` and `ngx_mruby_core_gems` from the
  `build_config.rb` of this release, and call `ngx_mruby_core_gems(conf)`
  in place of `conf.gembox 'full-core'`, as that file does. A build that
  needs fewer gems passes `NGX_MRUBY_CORE_GEMS - %w[...]`. To add a gem that
  the list leaves out, follow [Core gems](../install/README.md#core-gems).
- A build from a new checkout or a source archive gets the third-party
  mrbgems at the commits that `build_config.rb.lock` records
  ([The third-party mrbgems are built at the commits that `build_config.rb.lock` records](../releases/v3.0.0.md#the-third-party-mrbgems-are-built-at-the-commits-that-build_configrblock-records-558)).
  In a tree that keeps `mruby/build`, remove it after a change of the
  lock, before the next build; otherwise rake stops with
  `fatal: reference is not a tree` when a clone does not have the new
  commit:

  ```sh
  rm -rf mruby/build
  ```

  To build a gem at another commit, follow
  [Gem commits](../install/README.md#gem-commits-build_configrblock).
- The default build no longer has the auto-ssl mrbgem and the classes that
  came with it
  ([The default build leaves out the auto-ssl mrbgem and the classes that came with it](../releases/v3.0.0.md#the-default-build-leaves-out-the-auto-ssl-mrbgem-and-the-classes-that-came-with-it-556)).
  [Scripts](#scripts) says how to find the scripts that use them.
- No build of this release has the auto-ssl mrbgem, and the mruby build no
  longer reads `NGX_MRUBY_AUTO_SSL`
  ([The auto-ssl mrbgem and `NGX_MRUBY_AUTO_SSL` are removed](../releases/v3.0.0.md#the-auto-ssl-mrbgem-and-ngx_mruby_auto_ssl-are-removed-640)).
  Remove the variable from the environment of your builds; it has no
  effect. A server that gets its certificates with `Nginx::SSL::ACME`
  moves to nginx's
  [ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html)
  (nginx-acme) before the upgrade, or stays on 2.x. This finds the
  builds and the configurations that use them:

  ```sh
  grep -rnE 'NGX_MRUBY_AUTO_SSL|auto-ssl|Nginx::SSL::ACME' /path/to/build/scripts /path/to/nginx/conf
  ```
- With `./configure --with-mruby-incdir`, add
  `<mruby_root>/build/host/include` to the list of directories
  ([Sources that include `mruby.h` need the generated headers](../releases/v3.0.0.md#c-extensions-sources-that-include-mrubyh-need-the-generated-headers-561)).
- With mrbgems of your own or of third parties, see
  [C extensions and mrbgems](#c-extensions-and-mrbgems).

## Scripts

Most entries name a method that you can search for. This finds them in the
script files of a configuration (replace `/path/to/scripts` with the
directories of the files that the `*_handler` directives name):

```sh
grep -rnE 'Kernel\.|valid_encoding\?|allbits\?|anybits\?|nobits\?|remove_const|module_function|append_features|prepend_features|extend_object|singleton_method_added|\.(included|extended|prepended|inherited|method_added)\(|initialize_copy|respond_to_missing|respond_to\?|method_defined\?|method_missing|instance_methods|\.methods|iv_var|default_proc *=|FileTest|srand|Random\.new|Set\.new|Set\[|flatten_merge|RuntimeError|\.server *=|upstream_server *=' /path/to/scripts
```

Search the inline code of the `*_code` directives in the `nginx.conf`
files the same way. The items below say what to look for where a name is
not enough, and show the change.

- [`Hash#inspect` and `Hash#to_s` use a new format](../releases/v3.0.0.md#hashinspect-and-hashto_s-use-a-new-format-561):
  look for `inspect`, `to_s`, `"#{...}"` and `sprintf` or `format` with
  `%s` where the value can be a Hash or an Array of Hashes, and for `=>` in
  the strings that a script or a test compares with.

  ```ruby
  h = {"q" => "x"}
  Nginx.rputs h.to_s               # 2.x: {"q"=>"x"}   3.0.0: {"q" => "x"}
  Nginx.rputs JSON.generate(h)     # {"q":"x"} on both
  ```

- [`Set#inspect` and `Set#to_s` use a new format, and `Set#flatten_merge` is removed](../releases/v3.0.0.md#setinspect-and-setto_s-use-a-new-format-and-setflatten_merge-is-removed-561):
  the same search for a Set; `set.to_a.join(",")` gives the same string on
  both versions. The search above also finds `flatten_merge`:
  `s.flatten_merge(t)` becomes `s.merge(Set.new(t).flatten)`, which gives
  on both versions the Set that `s.flatten_merge(t)` gave on 2.x, when `t`
  is a Set or an Array. `s.merge(t.flatten)` gives that Set only when `t`
  is a Set: for an Array `t`, `Array#flatten` flattens the Arrays inside it
  and keeps the Sets, where `flatten_merge` did the opposite:

  ```ruby
  t = [2, Set.new([3])]
  Set.new([1]).flatten_merge(t)            # 2.x: the Set of 1, 2 and 3   3.0.0: NoMethodError
  Set.new([1]).merge(Set.new(t).flatten)   # the Set of 1, 2 and 3 on both
  Set.new([1]).merge(t.flatten)            # the Set of 1, 2 and a Set that holds 3, on both
  ```

- [The message of `NoMethodError` names the class of the receiver](../releases/v3.0.0.md#the-message-of-nomethoderror-names-the-class-of-the-receiver-561):
  look for `message` next to `rescue NoMethodError`, and for
  `undefined method` in scripts.

  ```ruby
  e.message == "undefined method 'foo'"   # 2.x: true   3.0.0: false (the message goes on with " for NilClass")
  ```

  Rescue `NoMethodError` itself instead of comparing the message.
- [`private` and `protected` are enforced](../releases/v3.0.0.md#private-and-protected-are-enforced-561):
  look for calls, with a receiver other than `self`, of `initialize`,
  `initialize_copy`, `respond_to_missing?` and `method_missing`, of methods
  defined with `def` at the top level, of `Kernel` methods such as `raise`,
  `sprintf` and `puts`, and of methods below `private` or `protected`. In
  handler code, a method defined with `def` at the top level stays public,
  and calls of it with a receiver need no change
  ([the proposal for #502](../proposals/archive/handler-code-frame.md#14-what-handler-code-shares-today),
  section 1.4). The search above finds the calls on `Kernel`
  (`Kernel\.`): only `Kernel.format`, `.sprintf`, `.raise`, `.sleep` and
  `.usleep` still work, and the others, such as `Kernel.Integer(x)`, become
  calls without a receiver. It also finds `instance_methods` and `methods`,
  which leave private methods out. Checking `respond_to?` before such a call
  does not help: it returns `true` for a private method.

  ```ruby
  class Router
    def call(r)
      pick(r)                  # no receiver: works on both
    end

    private

    def pick(r)
      r.uri
    end
  end

  Router.new.pick(r)           # 2.x: works   3.0.0: NoMethodError
  Router.new.send(:pick, r)    # works on both

  Kernel.Integer("12")         # 2.x: 12   3.0.0: NoMethodError (private method 'Integer' called for Module)
  Integer("12")                # 12 on both
  ```

- [`Module#remove_const`, `#private`, `#public`, `#protected`, `#module_function` and the hooks are private](../releases/v3.0.0.md#moduleremove_const-private-public-protected-module_function-and-the-hooks-are-private-561):
  the search above finds most of them; look also for `.private(`,
  `.public(` and `.protected(` called on a class or module. For example,
  `Foo.remove_const(:X)` becomes `Foo.send(:remove_const, :X)`.
- [Overrides of `append_features`, `prepend_features` and `extend_object` are not called](../releases/v3.0.0.md#overrides-of-append_features-prepend_features-and-extend_object-are-not-called-561):
  the search above finds them.

  ```ruby
  module Plugin
    def self.append_features(base)   # 3.0.0: never called, and no error
      base.extend(ClassMethods)
      super
    end
  end

  module Plugin
    def self.included(base)          # called on both
      base.extend(ClassMethods)
    end
  end
  ```

- [`allbits?`, `anybits?` and `nobits?` are methods of `Integer` only](../releases/v3.0.0.md#allbits-anybits-and-nobits-are-methods-of-integer-only-561):
  the search above finds them; `x.allbits?(1)` on a Float becomes
  `x.to_i.allbits?(1)`.
- [`FileTest` is a module](../releases/v3.0.0.md#filetest-is-a-module-561):
  the search above finds `FileTest`; only uses other than calls of its
  methods (`FileTest.exist?` and so on) need a change.
- [Assigning a constant in a method body is a `SyntaxError`](../releases/v3.0.0.md#assigning-a-constant-in-a-method-body-is-a-syntaxerror-561):
  compiling the scripts finds it (see [Checking the result](#checking-the-result)).

  ```ruby syntax-error
  def setup
    Table = {}                       # 3.0.0: SyntaxError when the script is compiled
    Object.const_set(:Table, {})     # works on both
  end
  ```

- [Float values have no bit operations](../releases/v3.0.0.md#float-values-have-no-bit-operations-561):
  look for `<<`, `>>`, `&`, `|`, `^` and `~` applied to a value that can be
  a Float: the result of `to_f`, of `Float()` or of arithmetic with a
  Float. The entry says how to get the number that 2.x gave.

  ```ruby
  x = 1.5
  x << 1                # 2.x: 3   3.0.0: NoMethodError
  (x * 2).to_i          # 3, the number of 2.x for x << 1
  x.to_i << 1           # 2, another number
  ```

- [`String#valid_encoding?` is not in the default build](../releases/v3.0.0.md#stringvalid_encoding-is-not-in-the-default-build-561):
  the search above finds it. With the default `build_config.rb` of 2.x the
  method returned `true` for every string, so a check like this one never
  rejected a request and can be removed:

  ```ruby
  Nginx.return Nginx::HTTP_BAD_REQUEST unless s.valid_encoding?
  ```

- [A seeded `Random` gives other numbers](../releases/v3.0.0.md#a-seeded-random-gives-other-numbers-561):
  the search above finds `srand` and `Random.new`; look also for tests that
  expect the numbers of a seeded generator.
- [`Hash#default_proc=` raises `TypeError` for an object that is not a Proc](../releases/v3.0.0.md#hashdefault_proc-raises-typeerror-for-an-object-that-is-not-a-proc-561):
  the search above finds it; pass a Proc, for example
  `h.default_proc = proc { |hash, key| hash[key] = [] }`.
- [`yield` with keyword arguments to a block with keyword parameters works](../releases/v3.0.0.md#yield-with-keyword-arguments-to-a-block-with-keyword-parameters-works-561):
  nothing to change; a `rescue ArgumentError` that was there for this case
  is no longer reached.
- [A `return` inside a block or a `for` body of handler code ends the code](../releases/v3.0.0.md#a-return-inside-a-block-or-a-for-body-of-handler-code-ends-the-code-561):
  nothing to change in the scripts. A `return` inside a block or the body
  of `for` at the top level of handler code no longer raises
  `LocalJumpError`: the handler answers with the response that its code set
  before the `return`, where 2.x answered 500 (2.7.0 answered 200 with the
  output that a content handler had written before it). Log alerts on
  `unexpected return (LocalJumpError)` no longer fire for it.
- [A content handler that ends without output answers 200 with an empty body instead of 500](../releases/v3.0.0.md#a-content-handler-that-ends-without-output-answers-200-with-an-empty-body-instead-of-500-574):
  look at the `mruby_content_handler` and `mruby_content_handler_code`
  handlers that can end without writing a body: a handler that writes only
  when a condition holds, one that passes a value that can be `""` or
  `nil` to `Nginx.rputs`, one that only sets response headers, and one
  that ends with `Nginx.return Nginx::HTTP_OK` or another status from 200
  to 299 other than 201 and 204. On 3.0.0 they answer that status (200
  when none is set) with `Content-Length: 0`; on 2.7.1 they answered 500.
  A handler that relied on the 500 sets the status that it means:

  ```ruby
  body = Nginx::Request.new.headers_in["X-Answer"].to_s
  Nginx.rputs body                       # body "": 2.7.1 answers 500   3.0.0 answers 200 with Content-Length: 0

  if body.empty?
    Nginx.return Nginx::HTTP_NOT_FOUND   # 404 on both
  else
    Nginx.rputs body
  end
  ```

- [An output body filter that ends with an empty body sends the response instead of closing the connection](../releases/v3.0.0.md#an-output-body-filter-that-ends-with-an-empty-body-sends-the-response-instead-of-closing-the-connection-574):
  nothing to change. A body filter that sets `""` with
  `Nginx::Filter#body=` or `#output`, or leaves the body of a response
  without a body empty, sends the status with `Content-Length: 0`, where
  2.7.2 and earlier closed the connection without a byte; 2.7.3 sends it
  as well.
- [The accessors of `Nginx::Var` become methods of `Nginx::Var` at their first use in a worker](../releases/v3.0.0.md#the-accessors-of-nginxvar-become-methods-of-nginxvar-at-their-first-use-in-a-worker-610):
  the search above finds `respond_to?`, `method_defined?`, `instance_methods`
  and `methods`; look at the ones on an `Nginx::Var` or on `Nginx::Var`
  itself. Their answer for a variable now depends on whether the worker has
  served an access of the name before. Use `exist?` instead:

  ```ruby
  v = Nginx::Var.new
  v.respond_to?(:request_method)   # 2.x: false   3.0.0: true after the first v.request_method in the worker
  v.exist?("request_method")       # true on both
  ```

  Also look for methods that the scripts define on `Object` or `Kernel`,
  for example with a `def` at the top level of handler code, whose name is
  also the name of a variable that a script reads with `v.NAME`. Once the
  accessor exists in a worker, `v.NAME` reads the variable instead of
  calling such a method. Rename the method. The search also finds
  `method_missing`: a script that wraps `Nginx::Var#method_missing`, for
  example with a module prepended to `Nginx::Var` whose `method_missing`
  calls `super`, sees only the first access of a name that gets an
  accessor. Move what the wrapper does to the code that reads the variable.
- [`Nginx::Connection`, `Nginx::Server` and `Nginx::Request` read their variables without calling `Nginx::Var`](../releases/v3.0.0.md#nginxconnection-nginxserver-and-nginxrequest-read-their-variables-without-calling-nginxvar-610):
  look for methods that a script defines on `Nginx::Var` (`class Nginx::Var`,
  `Nginx::Var.class_eval`, `define_method`) and for `iv_var`, which the search
  above finds. A method of `Nginx::Var` no longer changes what
  `Nginx::Connection#remote_ip` and the other methods of the entry return;
  define the method on their class instead, in `mruby_init_code`, which
  runs once when nginx reads the configuration. Handler code runs on every
  request in the same `mrb_state`, so there the second `alias_method` would
  make `nginx_remote_ip` a copy of the new `remote_ip`, which then calls
  itself:

  ```nginx
  mruby_init_code '
      class Nginx::Connection
        alias_method :nginx_remote_ip, :remote_ip
        def remote_ip
          Nginx::Request.new.headers_in["X-Real-IP"] || nginx_remote_ip   # works on both
        end
      end
  ';
  ```

- [`Dir` comes from mruby's core gem, and a closed `Dir` raises `IOError` instead of `RuntimeError`](../releases/v3.0.0.md#dir-comes-from-mrubys-core-gem-and-a-closed-dir-raises-ioerror-instead-of-runtimeerror-559):
  the search above finds `RuntimeError`; look at the ones that rescue an
  exception of a `Dir` that can be closed, or of `Dir.open` with a block
  that closes the `Dir`.

  ```ruby
  d = Dir.open(path)
  d.close
  begin
    d.read
  rescue RuntimeError            # 2.x: rescued   3.0.0: not rescued (IOError)
  end
  begin
    d.read
  rescue IOError, RuntimeError   # rescued on both
  end
  ```

- [`Nginx::Upstream#server=` and `Nginx::Stream::Connection#upstream_server=` raise `ArgumentError` for a string that cannot be a server](../releases/v3.0.0.md#nginxupstreamserver-and-nginxstreamconnectionupstream_server-raise-argumenterror-for-a-string-that-cannot-be-a-server-680):
  the search above finds both setters and `RuntimeError`; look at the ones
  that rescue an exception of a setter.

  ```ruby
  u = Nginx::Upstream.new "backend"
  begin
    u.server = "192.0.2.1:notaport"
  rescue RuntimeError                # 2.x: rescued   3.0.0: not rescued (ArgumentError)
  end
  begin
    u.server = "192.0.2.1:notaport"
  rescue ArgumentError, RuntimeError # rescued on both
  end
  ```

- [`Nginx::Upstream#server=` raises `ArgumentError` for a host name instead of resolving it](../releases/v3.0.0.md#nginxupstreamserver-raises-argumenterror-for-a-host-name-instead-of-resolving-it-680):
  the search above finds the setter; look at what the script gives it, also
  when the script reads the value from a request or a file.

  ```ruby
  u.server = "localhost:8080"        # 2.x: resolved while the worker waits   3.0.0: ArgumentError
  u.server = "127.0.0.1:8080"        # works on both
  ```

  Write an IPv4 address as four decimal numbers: `127.1` raises as well. For
  a name that does not change while nginx runs, write it in the `server` line
  of the `upstream {}` block and do not call the setter. nginx uses all the
  addresses of such a name: when it has more than one, `Nginx::Upstream.new`
  raises `RuntimeError` for that upstream, so remove that call too, or write an
  IP address in the `server` line. A name that does not resolve stops nginx at
  start.

- [The default build leaves out the auto-ssl mrbgem and the classes that came with it](../releases/v3.0.0.md#the-default-build-leaves-out-the-auto-ssl-mrbgem-and-the-classes-that-came-with-it-556):
  this finds the constants and the two `Dir` methods that the default
  build no longer has:

  ```sh
  grep -rnE 'Nginx::SSL::ACME|Acme|HttpRequest|OpenSSL|PolarSSL|SimpleHttp|(^|[^:])HTTP::|Base64|Forwardable|FORWARDABLE|Tempfile|tmpdir' /path/to/scripts
  ```

  `Base64`, `Dir.tmpdir` and `Dir.mktmpdir` have replacements in the
  default build:

  ```ruby
  Base64.encode(s)          # 3.0.0: NameError (uninitialized constant Base64)
  [s].pack('m0')            # the same string on both
  Base64.decode(b)          # 3.0.0: NameError
  b.unpack1('m')            # the same string on both
  Dir.tmpdir                # 3.0.0: NoMethodError
  ENV['TMPDIR'] || '/tmp'   # works on both
  ```

  For `Dir.mktmpdir`, see
  [The auto-ssl mrbgem and the classes that came with it](../install/README.md#the-auto-ssl-mrbgem-and-the-classes-that-came-with-it).
  The other constants need a `conf.gem` line of your own.

`Dir.children`, `Dir#each_child`, `Dir.empty?` and the methods of
`Enumerable` on a `Dir` are new to scripts of 2.x; the first two leave out
`.` and `..` (see [New features](../releases/v3.0.0.md#new-features)).

## Log monitoring

- [`Exception#inspect`, and so the `mrb_run failed` lines of `error.log`, use a new format](../releases/v3.0.0.md#exceptioninspect-and-so-the-mrb_run-failed-lines-of-errorlog-use-a-new-format-561):
  look in log parsers and alert rules for patterns on `mrb_run failed`
  lines, and for an exception class in parentheses at the end of a line.

  ```
  2.x:    mrb_run failed: return 500 HTTP status code to client: error: boom (RuntimeError)
  3.0.0:  mrb_run failed: return 500 HTTP status code to client: error: #<RuntimeError: boom>
  ```

  A pattern such as `\(RuntimeError\)$` becomes `#<RuntimeError: `.
- [The message of `NoMethodError` names the class of the receiver](../releases/v3.0.0.md#the-message-of-nomethoderror-names-the-class-of-the-receiver-561):
  a pattern that ends at `undefined method 'foo'` no longer matches, because
  the message goes on with ` for <class>`.
- [The messages logged while nginx reads the configuration are at the `info` level instead of `notice`](../releases/v3.0.0.md#the-messages-logged-while-nginx-reads-the-configuration-are-at-the-info-level-instead-of-notice-565):
  look in log parsers, alert rules and start scripts for `mechanism enabled`,
  `compile info`, `target variable` and `ngx_mruby NOTICE`. A start of
  nginx no longer writes these lines. `nginx -t` writes them at `[info]` to
  the startup log, which is the file given with `-e`, or else the error log
  path compiled into nginx (`logs/error.log` under the prefix by default).
  nginx copies a line of the startup log to the terminal only at `warn` and
  above, so the output of `nginx -t` does not show them.

  ```
  2.x, start:                 [notice] ... ngx_mruby/<version> (mruby/3.3.0) mechanism enabled in ...
  3.0.0, start:               no such line
  3.0.0, nginx -t:            [info] ... ngx_mruby/<version> (mruby/4.0.0) mechanism enabled in ...   (startup log only)
  3.0.0, nginx -t -e stderr:  [info] ... ngx_mruby/<version> (mruby/4.0.0) mechanism enabled in ...   (terminal)
  ```

  A check that looks for one of these lines to see that the module is
  loaded runs `nginx -t -e stderr` and reads its output, or reads the
  startup log after `nginx -t`:

  ```sh
  nginx -t -e stderr 2>&1 | grep 'mechanism enabled'
  ```

- [A content handler that ends without output answers 200 with an empty body instead of 500](../releases/v3.0.0.md#a-content-handler-that-ends-without-output-answers-200-with-an-empty-body-instead-of-500-574):
  a pattern on `response body is empty. return NGX_HTTP_INTERNAL_SERVER_ERROR`
  no longer matches for the content handlers of the main request that end
  without output and with no status or a status from 200 to 299 that nginx
  does not answer by itself; it still matches for a status below 200, and
  for `Nginx::HTTP_OK` without output in the other handlers and in
  subrequests.
- [An output body filter that ends with an empty body sends the response instead of closing the connection](../releases/v3.0.0.md#an-output-body-filter-that-ends-with-an-empty-body-sends-the-response-instead-of-closing-the-connection-574):
  an alert on `zero size buf in writer` no longer fires for these
  responses, because nginx sends them.

## C extensions and mrbgems

This finds the places in the C sources of a gem, or of a program that
embeds mruby, that the entries below are about:

```sh
grep -rnE 'Data_Wrap_Struct|mrb_data_object_alloc|MRB_SET_INSTANCE_TT|MRB_ARGS_|mruby/ext/io\.h|mrb_alloca|mrb_open|allocf|MRB_NO_PRESYM' src/
```

- [An object of a class not declared `MRB_TT_DATA` cannot wrap C data](../releases/v3.0.0.md#c-extensions-an-object-of-a-class-not-declared-mrb_tt_data-cannot-wrap-c-data-561):
  every class whose objects `Data_Wrap_Struct` or `mrb_data_object_alloc`
  creates needs the declaration after `mrb_define_class`:

  ```c
  struct RClass *c = mrb_define_class(mrb, "Uname", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);
  ```

- [mruby checks the argument count of a C method against its spec](../releases/v3.0.0.md#c-extensions-mruby-checks-the-argument-count-of-a-c-method-against-its-spec-561):
  compare the spec of each `mrb_define_method` with what its `mrb_get_args`
  reads, in both directions. A method defined with `MRB_ARGS_REQ(2)` that
  reads one string (`mrb_get_args(mrb, "S", &s)`) and is called with one
  argument raises `ArgumentError`; define it with `MRB_ARGS_REQ(1)`. A
  method defined with `MRB_ARGS_REQ(1)` that reads `"o|o"` and is called
  with two arguments raises too; define it with `MRB_ARGS_ARG(1, 1)`.
- [Renamed headers and functions, and `mrb_open()` on failure](../releases/v3.0.0.md#c-extensions-renamed-headers-and-functions-and-mrb_open-on-failure-561):

  ```c
  #include <mruby/io.h>                    /* was <mruby/ext/io.h> */
  void *buf = mrb_temp_alloc(mrb, size);   /* was mrb_alloca(mrb, size) */
  mrb_state *mrb = mrb_open();             /* also in place of mrb_open_allocf(my_allocf, ud) */
  if (MRB_OPEN_FAILURE(mrb)) { /* ... */ } /* was: if (mrb == NULL) */

  /* a custom allocator, in place of mrb_default_allocf() or my_allocf */
  void *mrb_basic_alloc_func(void *ptr, size_t size) { /* ... */ }
  ```

- [Sources that include `mruby.h` need the generated headers](../releases/v3.0.0.md#c-extensions-sources-that-include-mrubyh-need-the-generated-headers-561):
  add `-I<mruby>/build/host/include` next to `-I<mruby>/include` where you
  compile such a source outside the mruby build.

## Checking the result

1. Compile every script with the `mrbc` of mruby 4.0.0. After a build of
   this release (`sh build.sh` or `sh test.sh`), `mruby/bin/mrbc -c` checks
   the syntax of a script: it prints `Syntax OK`, or the line of the error
   (for a constant assigned in a method body,
   `<file>:2:3: dynamic constant assignment`) and exits with 1.

   ```sh
   for f in /path/to/scripts/*.rb; do mruby/bin/mrbc -c "$f" || echo "check: $f"; done
   ```

2. Run the parts of a script that do not call the `Nginx` classes with both
   versions of mruby. The entries of mruby 4.0.0 were measured this way
   between 2026-10-04 and 2026-10-14: the same Ruby script ran with two
   `mruby` binaries, one built from the mruby tree of ngx_mruby 2.x (mruby
   3.3.0) and one from mruby 4.0.0, in Docker (Ubuntu 22.04, gcc 11), with
   mruby's `default` gembox or with the core gems of each version's
   ngx_mruby build (`full-core` and iij/mruby-dir for 3.3.0,
   `NGX_MRUBY_CORE_GEMS` for 4.0.0). The entries that say "the test
   suite of ngx_mruby saw the change" also changed a response or a log line
   of ngx_mruby itself. To do the same, copy the `mruby/` directory of each
   version to a directory of its own, run `rake MRUBY_CONFIG=default` in
   each copy, and run your script with the `bin/mruby` of both copies. Do
   not run that rake in the `mruby/` of an ngx_mruby checkout: it builds
   into `mruby/build`, where the build of the module keeps its mruby.
3. Run the configuration with the module of this release on a test server,
   send the requests that reach each handler, and look in `error.log` for
   `mrb_run failed` lines with `NoMethodError`, `TypeError`,
   `ArgumentError` or `SyntaxError`.

These were checked the same way and did not change, so they need no check:
`String#size` and `#length` count bytes (the mruby-encoding gem is not in
the default build; see [Core gems](../install/README.md#core-gems)); the
`ArgumentError` for a wrong number of arguments; `Exception#message`;
`Struct#inspect`; `Float#to_s`; Integer division and modulo; `Kernel#sleep`
and `#usleep` (from mruby-sleep).
