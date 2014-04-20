#!/bin/sh

# Default install
#   download nginx into ./build/
#   build into ./build/nginx

# ENV example
#
#   NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.4.4' NGINX_SRC_ENV='/usr/local/src/nginx-1.4.4' sh build.sh
#

set -e

. ./nginx_version                                                                

if [ $NGINX_CONFIG_OPT_ENV ]; then
    NGINX_CONFIG_OPT=$NGINX_CONFIG_OPT_ENV
else
    NGINX_CONFIG_OPT='--prefix='`pwd`'/build/nginx'
fi

echo "apxs="$APXS_PATH "apachectl="$APACHECTL_PATH

if [ ! -d "./mruby/src" ]; then
    echo "mruby Downloading ..."
    git submodule init
    git submodule update
    echo "mruby Downloading ... Done"
fi
cd mruby
if [ -d "./build" ]; then
    echo "mruby Cleaning ..."
    ./minirake clean
    echo "mruby Cleaning ... Done"
fi
cd ..

if [ $NGINX_SRC_ENV ]; then
    NGINX_SRC=$NGINX_SRC_ENV
else
    echo "nginx Downloading ..."
    if [ -d "./build" ]; then
        echo "build directory was found"
    else
        mkdir build
    fi
    cd build                                                                         
    if [ ! -e ${NGINX_SRC_VER} ]; then                                               
        wget http://nginx.org/download/${NGINX_SRC_VER}.tar.gz                       
        echo "nginx Downloading ... Done"                                            
        tar xf ${NGINX_SRC_VER}.tar.gz                                               
    fi                                                                               
    ln -sf ${NGINX_SRC_VER} nginx_src                                                
    NGINX_SRC=`pwd`'/nginx_src'                                                      
    cd ..                                                                            
fi

echo "ngx_mruby configure ..."
./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="${NGINX_CONFIG_OPT}"
echo "ngx_mruby configure ... Done"

echo "mruby building ..."
make build_mruby
echo "mruby building ... Done"

echo "ngx_mruby building ..."
make
echo "ngx_mruby building ... Done"

echo "build.sh ... successful"

#sudo make install
