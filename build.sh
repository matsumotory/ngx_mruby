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

if [ -n "$BUILD_DYNAMIC_MODULE" ]; then
    BUILD_DIR='build_dynamic'
    NGINX_INSTALL_DIR=`pwd`'/build_dynamic/nginx'
else
    BUILD_DIR='build'
    NGINX_INSTALL_DIR=`pwd`'/build/nginx'
fi

if [ "$NGINX_CONFIG_OPT_ENV" != "" ]; then
    NGINX_CONFIG_OPT=$NGINX_CONFIG_OPT_ENV
else
    NGINX_CONFIG_OPT="--prefix=${NGINX_INSTALL_DIR} --with-http_stub_status_module --with-stream --without-stream_access_module"
fi

if [ "$NUM_THREADS_ENV" != "" ]; then
    NUM_THREADS=$NUM_THREADS_ENV
else
    NUM_PROCESSORS=`getconf _NPROCESSORS_ONLN`
    if [ $NUM_PROCESSORS -gt 1 ]; then
        NUM_THREADS=$(expr $NUM_PROCESSORS / 2)
    else
        NUM_THREADS=1
    fi
fi

echo "NGINX_CONFIG_OPT=$NGINX_CONFIG_OPT"
echo "NUM_THREADS=$NUM_THREADS"

cd mruby
if [ -d "./${BUILD_DIR}" ]; then
    echo "mruby Cleaning ..."
    ./minirake clean
    echo "mruby Cleaning ... Done"
fi
cd ..

if [ $NGINX_SRC_ENV ]; then
    NGINX_SRC=$NGINX_SRC_ENV
else
    echo "nginx Downloading ..."
    if [ -d "./${BUILD_DIR}" ]; then
        echo "build directory was found"
    else
        mkdir ${BUILD_DIR}
    fi
    cd ${BUILD_DIR}
    if [ ! -e ${NGINX_SRC_VER} ]; then
        wget http://nginx.org/download/${NGINX_SRC_VER}.tar.gz
        echo "nginx Downloading ... Done"
        tar xf ${NGINX_SRC_VER}.tar.gz
    fi
    ln -snf ${NGINX_SRC_VER} nginx_src
    NGINX_SRC=`pwd`'/nginx_src'
    cd ..
fi

echo "ngx_mruby configure ..."
./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="${NGINX_CONFIG_OPT}" $@
echo "ngx_mruby configure ... Done"

if [ -n "$BUILD_DYNAMIC_MODULE" ]; then
    echo "mruby building for suppot dynamic module ..."
    make build_mruby_with_fpic NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
    echo "mruby building for suppot dynamic module ... Done"

    echo "ngx_mruby building as dynamic module ..."
    make ngx_mruby_dynamic NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
    echo "ngx_mruby building ... Done"
else
    echo "mruby building ..."
    make build_mruby NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
    echo "mruby building ... Done"

    echo "ngx_mruby building ..."
    make NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
    echo "ngx_mruby building ... Done"
fi

echo "build.sh ... successful"

#sudo make install
