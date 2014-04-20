#!/bin/sh

# Default install and test
#   download nginx into ./build/
#   build into ./build/nginx
#   test on ./build/nginx

set -e

. ./nginx_version                                                           

NGINX_INSTALL_DIR=`pwd`'/build/nginx'
NGINX_CONFIG_OPT='--prefix='${NGINX_INSTALL_DIR}

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

echo "ngx_mruby configure ..."
./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="${NGINX_CONFIG_OPT}"
echo "ngx_mruby configure ... Done"

echo "mruby building ..."
make build_mruby
echo "mruby building ... Done"

echo "ngx_mruby building ..."
make
echo "ngx_mruby building ... Done"

echo "ngx_mruby testing ..."
make install
cp -p test/build_config.rb ./mruby/.
cp -p test/conf/nginx.conf ${NGINX_INSTALL_DIR}/conf/.
cp -p test/html/* ${NGINX_INSTALL_DIR}/html/.
cp -p test/t/ngx_mruby.rb ./mruby/test/t/.
${NGINX_INSTALL_DIR}/sbin/nginx &
sleep 2
cd mruby
rake clean
rake all test
killall nginx
echo "ngx_mruby testing ... Done"

echo "test.sh ... successful"
