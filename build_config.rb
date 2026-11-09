# The mruby core gems of the nginx side (host) and of the test client (test),
# selected by name. `conf.gembox 'full-core'` takes every core gem that the
# vendored mruby has, so an mruby update would change the classes and methods
# available to ngx_mruby scripts without a change here. For example, the
# full-core of mruby 4.1.0-rc2 takes mruby-task, which redefines Kernel#sleep
# and whose POSIX implementation arms a process-wide SIGALRM interval timer,
# and leaves mruby-sleep out.
#
# This list is the set that full-core selected in mruby 3.3.0, updated for
# mruby 4.0.0 and 4.1.0-rc2 as follows. Adding or removing a name changes what
# scripts can use; decide each one on its own.
# - mruby-print is gone: mruby 3.4 removed it, and Kernel#print, #puts and #p
#   come from mruby-io (from the core without mruby-io).
# - mruby 4.1 has no hal-* gems: the POSIX back ends that mruby-io, mruby-dir
#   and mruby-socket of mruby 4.0.0 took from hal-posix-io, hal-posix-dir and
#   hal-posix-socket are part of those gems (ports/posix/), so the list has no
#   back end names.
# - Left out, although full-core of 4.1.0-rc2 takes them:
#   - mruby-task: it redefines Kernel#sleep,
#     arms a SIGALRM interval timer in every process that opens an mrb_state,
#     and limits the number of mrb_states (MRB_TASK_MAX_VMS).
#   - mruby-encoding: it defines MRB_UTF8_STRING for the whole build, so
#     String#size, #[] and #index count characters instead of bytes, and a
#     script that computes a Content-Length from String#size gets another
#     number. Leaving it out removes String#valid_encoding? from scripts:
#     mruby 3.3 defined it in mruby-string-ext, and since mruby 3.4 only
#     mruby-encoding defines it, so a call raises NoMethodError. A script
#     that needs it has to take mruby-encoding or drop the call; without
#     MRB_UTF8_STRING, the 3.3 method returned true for every string, even
#     "\xfe". The owner decided on 2026-10-04 to leave the gem out of the
#     default build and to keep it opt-in (see "Core gems" in
#     docs/install/README.md).
#   - mruby-strftime (Time#strftime) and mruby-benchmark (Benchmark): new in
#     mruby 4.0; each would add an API that ngx_mruby has not had, which is
#     a decision of its own.
#   - mruby-regexp (Regexp): new in mruby 4.1. mattn/mruby-onig-regexp below
#     defines Regexp, and 3.0 keeps it (item 1 of section 7 of
#     docs/proposals/v3-plan.md).
#   - mruby-string-bitops (bit operations on String) and mruby-bin-mrb (the
#     mrb command): new in mruby 4.1; each would add an API that ngx_mruby
#     has not had, which is a decision of its own.
# - mruby-env (ENV), mruby-process (Process) and mruby-signal (Signal) are
#   in: new in mruby 4.1, they replace iij/mruby-env and iij/mruby-process,
#   which have the same gem names and have had no commit since 2018 and
#   2019 (section 3.3 of docs/proposals/v3-plan.md). mruby-process depends on
#   mruby-signal, so the list names mruby-signal as well, to show that
#   scripts get Signal (Signal.list and Signal.signame, no Signal.trap).
#   iij/mruby-process also defined Kernel#sleep, #exit, #exit!, #fork and
#   #system, which replaced those of mruby-sleep and mruby-exit; the core
#   gem defines none of them (docs/releases/v3.0.0.md).
# - Left out, as full-core leaves them out: mruby-bin-debugger, mruby-test;
#   and the hardware gems hw-* of mruby 4.1.
# - mruby-sleep stays: full-core of 4.1.0-rc2 leaves it out in favour of
#   mruby-task, but Kernel#sleep and #usleep of ngx_mruby scripts come from it.
# mruby-test-inline-struct has only tests and adds nothing to libmruby.
NGX_MRUBY_CORE_GEMS = %w[
  mruby-array-ext mruby-bigint mruby-bin-config mruby-bin-mirb mruby-bin-mrbc
  mruby-bin-mruby mruby-bin-strip mruby-binding mruby-catch mruby-class-ext
  mruby-cmath mruby-compar-ext mruby-compiler mruby-complex mruby-data
  mruby-dir mruby-enum-chain mruby-enum-ext mruby-enum-lazy mruby-enumerator
  mruby-env mruby-errno mruby-error mruby-eval mruby-exit mruby-fiber
  mruby-hash-ext mruby-io mruby-kernel-ext mruby-math mruby-metaprog
  mruby-method mruby-numeric-ext mruby-object-ext mruby-objectspace
  mruby-os-memsize mruby-pack mruby-proc-binding mruby-proc-ext
  mruby-process mruby-random mruby-range-ext mruby-rational mruby-set
  mruby-signal mruby-sleep mruby-socket
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
  # ENV, Process and Dir come from the core gems mruby-env, mruby-process
  # and mruby-dir (in NGX_MRUBY_CORE_GEMS), in place of iij/mruby-env,
  # iij/mruby-process and iij/mruby-dir.
  conf.gem github: 'iij/mruby-digest'
  conf.gem github: 'mattn/mruby-json'
  conf.gem github: 'mattn/mruby-onig-regexp'
  conf.gem github: 'matsumotory/mruby-redis'
  conf.gem github: 'matsumotory/mruby-userdata'
  # build_config.rb.lock pins mruby-uname (here and in the test build) to the
  # merge commit of matsumotory/mruby-uname#1 on the gem's master, which
  # declares the instances of Uname as data objects: with mruby 4.0, every
  # method of Uname at the commits before it raises "TypeError: allocation
  # failure of Uname".
  conf.gem github: 'matsumotory/mruby-uname'
  conf.gem github: 'matsumotory/mruby-mutex'
  conf.gem github: 'monochromegane/mruby-secure-random'

  # ngx_mruby extended class
  conf.gem './mrbgems/ngx_mruby_mrblib'
  conf.gem './mrbgems/rack-based-api'

  # Left out of the default build since 3.0.0 (docs/releases/v3.0.0.md):
  # Vedis, an embedded key-value store; its build clones symisc/vedis at the
  # head of its default branch, which has had no commit since 2021-11.
  # conf.gem github: 'matsumotory/mruby-vedis'
  # Cache, a key-value store in shared memory, on a copy of the
  # localmemcache library in the gem's sources; sck/localmemcache has had
  # no commit since 2013-05.
  # conf.gem github: 'matsumotory/mruby-localmemcache'

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

  # mruby-simplehttp depends on mruby-polarssl (HTTPS in SimpleHttp) unless
  # NO_SSL is set in the environment, and mruby-polarssl depends on
  # mruby-print, which mruby 3.4 removed, so the test build would stop while
  # rake loads the gems. The suite sends HTTPS requests with curl and
  # `openssl s_client`, never with HttpRequest, so the test client builds
  # SimpleHttp without HTTPS. rake loads the gems of all builds in one process,
  # so this also applies to a host build of your own that has mruby-simplehttp.
  ENV['NO_SSL'] ||= '1'

  conf.gem github: 'matsumotory/mruby-simplehttp'
  conf.gem github: 'matsumotory/mruby-httprequest'
  # pinned by build_config.rb.lock to the same commit as in the host build
  conf.gem github: 'matsumotory/mruby-uname'
  conf.gem github: 'matsumotory/mruby-simpletest'
  conf.gem github: 'mattn/mruby-http'
  conf.gem github: 'mattn/mruby-json'

  # The core gems listed at the top of this file (ENV comes from mruby-env),
  # without Process and Signal: the test client has never had Process, and
  # the cases that need it are CRuby helpers (test/t/cases/_*.rb).
  ngx_mruby_core_gems(conf, NGX_MRUBY_CORE_GEMS - %w[mruby-process mruby-signal])
end
