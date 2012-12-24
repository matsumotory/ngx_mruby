##
##  Makefile -- Build procedure for ngx_mruby for nginx module
##	  MATSUMOTO, Ryosuke
##

# target source
NGINX=http://nginx.org/download/nginx-1.2.2.tar.gz
NGINXS=nginx-1.2.2.tar.gz
NGINXD=nginx-1.2.2
INSTALL=/usr/local/nginx122

MRUBY_ROOT=./mruby
ENABLE_GEMS=true

#   suport mrbgems
ifeq ($(ENABLE_GEMS),false)
  GEM_ARCHIVE_FILES =
else
  MAKEFILE_GEM_LIST := $(MRUBY_ROOT)/mrbgems/g/MakefileGemList
  ifeq ($(wildcard $(MAKEFILE_GEM_LIST)),)
    GEM_ARCHIVE_FILES =
  else
    include $(MAKEFILE_GEM_LIST)
    NGX_MRUBY_CFLAGS = $(GEM_CFLAGS_LIST) $(MRUBY_ROOT)/include
  endif
endif

#   the default target
all: ngx_mruby

##   build for iij extended lib
#extend: libmruby-ex.a tmp/nginx

#   install
install:
	cd tmp/nginx-1.2.2 && make install

#   cleanup
clean:
	-rm -rf tmp mrbgems_config

# nginx 1.2.2
ngx_mruby:
	@echo CORE_LIBS=\"\$$CORE_LIBS $(GEM_LDFLAGS_LIST) $(GEM_ARCHIVE_FILES) $(GEM_LIBS_LIST)\" > ./mrbgems_config
	@echo CORE_INCS=\"\$$CORE_INCS $(NGX_MRUBY_CFLAGS)\" >> ./mrbgems_config
	mkdir -p tmp
	cd tmp && wget $(NGINX)
	cd tmp && tar xvf $(NGINXS)
	cd tmp/$(NGINXD) && ./configure --add-module=../../ --prefix=$(INSTALL) && make

# libmruby.a
#tmp/mruby:
#	mkdir -p tmp vendors
#	cd tmp; git clone git://github.com/mruby/mruby.git
#
#libmruby.a: tmp/mruby
#	cd $(MRUBY_ROOT) && rake ENABLE_GEMS=$(ENABLE_GEMS)
#	cp -r tmp/mruby/include vendors/
#	cp -r tmp/mruby/lib vendors/
#	cp -r tmp/mruby/src vendors/
#	cp -r tmp/mruby/bin vendors/
#	cp -r tmp/mruby/mrblib vendors/
#
## libmruby.a (+iij extended lib)
#tmp/mruby-ex:
#	mkdir -p tmp vendors
#	cd tmp; git clone git://github.com/iij/mruby.git
#
#libmruby-ex.a: tmp/mruby-ex
#	cd tmp/mruby && make
#	cp -r tmp/mruby/include vendors/
#	cp -r tmp/mruby/lib vendors/
#	cp -r tmp/mruby/src vendors/
#	cp -r tmp/mruby/bin vendors/
#	cp -r tmp/mruby/mrblib vendors/
