##
##  Makefile -- Build procedure for ngx_mruby for nginx module
##	  MATSUMOTO, Ryosuke
##

# target source
NGINX=http://nginx.org/download/nginx-1.2.2.tar.gz
NGINXS=nginx-1.2.2.tar.gz
NGINXD=nginx-1.2.2
INSTALL=/usr/local/nginx122

#   the default target
all: libmruby.a tmp/nginx

#   build for iij extended lib
extend: libmruby-ex.a tmp/nginx

#   install
install:
	cd tmp/nginx-1.2.2 && make install

#   cleanup
clean:
	-rm -rf tmp vendors

# nginx 1.2.2
tmp/nginx:
	mkdir -p tmp vendors
	cd tmp && wget $(NGINX)
	cd tmp && tar xvf $(NGINXS)
	cd tmp/$(NGINXD) && ./configure --add-module=../../ --prefix=$(INSTALL) && make

# libmruby.a
tmp/mruby:
	mkdir -p tmp vendors
	cd tmp; git clone https://github.com/mruby/mruby.git

libmruby.a: tmp/mruby
	cd tmp/mruby && make
	cp -r tmp/mruby/include vendors/
	cp -r tmp/mruby/lib vendors/
	cp -r tmp/mruby/src vendors/
	cp -r tmp/mruby/bin vendors/
	cp -r tmp/mruby/mrblib vendors/

# libmruby.a (+iij extended lib)
tmp/mruby-ex:
	mkdir -p tmp vendors
	cd tmp; git clone git://github.com/iij/mruby.git

libmruby-ex.a: tmp/mruby-ex
	cd tmp && make
	cp -r tmp/mruby/include vendors/
	cp -r tmp/mruby/lib vendors/
	cp -r tmp/mruby/src vendors/
	cp -r tmp/mruby/bin vendors/
	cp -r tmp/mruby/mrblib vendors/
