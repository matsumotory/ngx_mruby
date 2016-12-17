#
# Dockerfile for ngx_mruby on ubuntu 14.04 64bit
#

#
# Using Docker Image matsumotory/ngx-mruby
#
# Pulling
#   docker pull matsumotory/ngx-mruby
#
# Running
#  docker run -d -p 10080:80 matsumotory/ngx-mruby
#
# Access
#   curl http://127.0.0.1:10080/mruby-hello
#

#
# Manual Build
#
# Building
#   docker build -t your_name:ngx_mruby .
#
# Runing
#   docker run -d -p 10080:80 your_name:ngx_mruby
#
# Access
#   curl http://127.0.0.1:10080/mruby-hello
#

FROM ubuntu:14.04
MAINTAINER matsumotory

RUN apt-get -y update
RUN apt-get -y install sudo openssh-server
RUN apt-get -y install git
RUN apt-get -y install curl
RUN apt-get -y install rake
RUN apt-get -y install ruby2.0 ruby2.0-dev
RUN apt-get -y install bison
RUN apt-get -y install libcurl4-openssl-dev
RUN apt-get -y install libhiredis-dev
RUN apt-get -y install libmarkdown2-dev
RUN apt-get -y install libcap-dev
RUN apt-get -y install libcgroup-dev
RUN apt-get -y install make
RUN apt-get -y install libpcre3 libpcre3-dev
RUN apt-get -y install libmysqlclient-dev

RUN cd /usr/local/src/ && git clone https://github.com/matsumotory/ngx_mruby.git
ENV NGINX_CONFIG_OPT_ENV --with-http_stub_status_module --with-http_ssl_module --prefix=/usr/local/nginx --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module
RUN cd /usr/local/src/ngx_mruby && sh build.sh && make install

EXPOSE 80
EXPOSE 443

ONBUILD ADD docker/hook /usr/local/nginx/hook
ONBUILD ADD docker/conf /usr/local/nginx/conf
ONBUILD ADD docker/conf/nginx.conf /usr/local/nginx/conf/nginx.conf

CMD ["/usr/local/nginx/sbin/nginx"]
