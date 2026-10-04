# The mruby core gems of the nginx side (host) and of the test client (test),
# selected by name. `conf.gembox 'full-core'` takes every core gem that the
# vendored mruby has, so an mruby update would change the classes and methods
# available to ngx_mruby scripts without a change here. For example, the
# full-core of mruby 4.0.0 and of 4.1.0-rc2 takes mruby-task, which redefines
# Kernel#sleep and whose POSIX implementation arms a process-wide SIGALRM
# interval timer, and leaves mruby-sleep out.
# This list is the set that full-core selects in mruby 3.3.0. Adding or
# removing a name changes what scripts can use; decide each one on its own.
# mruby-test-inline-struct has only tests and adds nothing to libmruby.
NGX_MRUBY_CORE_GEMS = %w[
  mruby-array-ext mruby-bigint mruby-bin-config mruby-bin-mirb mruby-bin-mrbc
  mruby-bin-mruby mruby-bin-strip mruby-binding mruby-catch mruby-class-ext
  mruby-cmath mruby-compar-ext mruby-compiler mruby-complex mruby-data
  mruby-dir mruby-enum-chain mruby-enum-ext mruby-enum-lazy mruby-enumerator
  mruby-errno mruby-error mruby-eval mruby-exit mruby-fiber mruby-hash-ext
  mruby-io mruby-kernel-ext mruby-math mruby-metaprog mruby-method
  mruby-numeric-ext mruby-object-ext mruby-objectspace mruby-os-memsize
  mruby-pack mruby-print mruby-proc-binding mruby-proc-ext mruby-random
  mruby-range-ext mruby-rational mruby-set mruby-sleep mruby-socket
  mruby-sprintf mruby-string-ext mruby-struct mruby-symbol-ext
  mruby-test-inline-struct mruby-time mruby-toplevel-ext
].freeze

# Adds the core gems named in `names` to the build `conf`. A name that the
# mruby being built does not have (a gem of another mruby version) stops the
# build, so that an mruby update cannot drop a gem from the list unnoticed.
# While the vendored mruby is being updated, NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1
# in the environment skips such names with a notice instead. A build that
# needs fewer gems passes `NGX_MRUBY_CORE_GEMS - %w[...]`.
def ngx_mruby_core_gems(conf, names = NGX_MRUBY_CORE_GEMS)
  gem_dir = File.join(MRUBY_ROOT, 'mrbgems')
  missing = names.reject { |name| File.file?(File.join(gem_dir, name, 'mrbgem.rake')) }
  unless missing.empty?
    message = "build_config.rb: core gem(s) #{missing.join(', ')} not in #{gem_dir} " \
              "(#{conf.name} build)"
    unless ENV['NGX_MRUBY_ALLOW_MISSING_CORE_GEMS'] == '1'
      raise "#{message}. Edit NGX_MRUBY_CORE_GEMS in build_config.rb, or set " \
            'NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1 to skip them while updating mruby.'
    end
    $stderr.puts "#{message}; skipped because NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1"
  end
  (names - missing).each { |name| conf.gem core: name }
end

MRuby::Build.new('host') do |conf|
  toolchain :gcc

  conf.defines << 'MRB_STR_LENGTH_MAX=10485760'
  ngx_mruby_core_gems(conf)

  conf.cc do |cc|
    cc.flags << ENV['NGX_MRUBY_CFLAGS'] if ENV['NGX_MRUBY_CFLAGS']
  end

  conf.linker do |linker|
    linker.flags << ENV['NGX_MRUBY_LDFLAGS'] if ENV['NGX_MRUBY_LDFLAGS']
    linker.libraries << ENV['NGX_MRUBY_LIBS'].split(',') if ENV['NGX_MRUBY_LIBS']
  end

  #
  # Recommended for ngx_mruby
  #
  # The third-party gems are built at the commits recorded in
  # build_config.rb.lock (see docs/install/README.md). Declare them with
  # github:, not mgem:, so that the URL comes from this file and not from
  # mruby's clone of mruby/mgem-list, which no lock pins.
  conf.gem github: 'iij/mruby-env'
  # Dir comes from the core gem mruby-dir (in NGX_MRUBY_CORE_GEMS), which
  # started as iij/mruby-dir and has every method that one has.
  conf.gem github: 'iij/mruby-digest'
  conf.gem github: 'iij/mruby-process'
  conf.gem github: 'mattn/mruby-json'
  conf.gem github: 'mattn/mruby-onig-regexp'
  # disabled: unpinned hiredis clone in mrbgem.rake fails CI (upstream FFC_DEBUG -Wundef/-Werror)
  # conf.gem github: 'matsumotory/mruby-redis'
  conf.gem github: 'matsumotory/mruby-vedis'
  conf.gem github: 'matsumotory/mruby-userdata'
  conf.gem github: 'matsumotory/mruby-uname'
  conf.gem github: 'matsumotory/mruby-mutex'
  conf.gem github: 'matsumotory/mruby-localmemcache'
  conf.gem github: 'monochromegane/mruby-secure-random'

  # ngx_mruby extended class
  conf.gem './mrbgems/ngx_mruby_mrblib'
  conf.gem './mrbgems/rack-based-api'

  # auto-ssl (Nginx::SSL::ACME) is built only with NGX_MRUBY_AUTO_SSL=1 in the
  # environment of the mruby build (see docs/install/README.md). Its ACME
  # client speaks ACMEv1, and it brings in pyama86/mruby-acme-client,
  # pyama86/mruby-polarssl (GPL) and their dependencies mruby-httprequest,
  # mruby-simplehttp, mruby-http, mruby-base64, mruby-forwardable and
  # mruby-tempfile, which no other gem of this build needs.
  conf.gem './mrbgems/auto-ssl' if ENV['NGX_MRUBY_AUTO_SSL'] == '1'

  # use memcached
  # conf.gem :github => 'matsumotory/mruby-memcached'

  # build error on travis ci 2014/12/01, commented out mruby-file-stat
  # conf.gem :github => 'ksss/mruby-file-stat'

  # use markdown on ngx_mruby
  # conf.gem :github => 'matsumotory/mruby-discount'

  # use mysql on ngx_mruby
  # conf.gem :github => 'mattn/mruby-mysql'

  # have GeoIPCity.dat
  # conf.gem :github => 'matsumotory/mruby-geoip'

  # Linux only for ngx_mruby
  # conf.gem :github => 'matsumotory/mruby-capability'
  # conf.gem :github => 'matsumotory/mruby-cgroup'
end

MRuby::Build.new('test') do |conf|
  # load specific toolchain settings

  conf.defines << 'MRB_STR_LENGTH_MAX=10485760'
  # Gets set by the VS command prompts.
  if ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  enable_debug

  conf.gem github: 'matsumotory/mruby-simplehttp'
  conf.gem github: 'matsumotory/mruby-httprequest'
  conf.gem github: 'matsumotory/mruby-uname'
  conf.gem github: 'matsumotory/mruby-simpletest'
  conf.gem github: 'mattn/mruby-http'
  conf.gem github: 'mattn/mruby-json'
  conf.gem github: 'iij/mruby-env'

  # the core gems listed at the top of this file
  ngx_mruby_core_gems(conf)
end
