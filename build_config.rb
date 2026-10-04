MRuby::Build.new('host') do |conf|
  toolchain :gcc

  conf.defines << 'MRB_STR_LENGTH_MAX=10485760'
  conf.gembox 'full-core'

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
  conf.gem github: 'iij/mruby-env'
  conf.gem github: 'iij/mruby-dir'
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
  conf.gem mgem: 'mruby-secure-random'

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

  # include the default GEMs
  conf.gembox 'full-core'
end
