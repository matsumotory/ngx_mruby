MRuby::Build.new do |conf|

  toolchain :gcc

  conf.gembox 'full-core'

  #
  # Recommended for ngx_mruby
  #
  conf.gem :github => 'iij/mruby-io'
  conf.gem :github => 'iij/mruby-env'
  conf.gem :github => 'iij/mruby-dir'
  conf.gem :github => 'iij/mruby-digest'
  conf.gem :github => 'iij/mruby-process'
  conf.gem :github => 'iij/mruby-pack'
  conf.gem :github => 'iij/mruby-socket'
  conf.gem :github => 'mattn/mruby-json'
  conf.gem :github => 'mattn/mruby-onig-regexp'
  conf.gem :github => 'matsumoto-r/mruby-redis'
  conf.gem :github => 'matsumoto-r/mruby-vedis'
  conf.gem :github => 'matsumoto-r/mruby-sleep'
  conf.gem :github => 'matsumoto-r/mruby-userdata'
  conf.gem :github => 'matsumoto-r/mruby-uname'
  conf.gem :github => 'matsumoto-r/mruby-mutex'
  conf.gem :github => 'matsumoto-r/mruby-localmemcache'

  # ngx_mruby extended class
  conf.gem './mrbgems/ngx_mruby_mrblib'
  conf.gem './mrbgems/rack-based-api'

  # use memcached
  # conf.gem :github => 'matsumoto-r/mruby-memcached'

  # build error on travis ci 2014/12/01, commented out mruby-file-stat
  # conf.gem :github => 'ksss/mruby-file-stat'

  # use markdown on ngx_mruby
  # conf.gem :github => 'matsumoto-r/mruby-discount'

  # use mysql on ngx_mruby
  #conf.gem :github => 'mattn/mruby-mysql'

  # have GeoIPCity.dat
  # conf.gem :github => 'matsumoto-r/mruby-geoip'

  # Linux only for ngx_mruby
  # conf.gem :github => 'matsumoto-r/mruby-capability'
  # conf.gem :github => 'matsumoto-r/mruby-cgroup'

end
