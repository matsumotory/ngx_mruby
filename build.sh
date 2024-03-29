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

# OS specific configuration
if [ `uname -s` = "NetBSD" ]; then
    NPROCESSORS_ONLN="NPROCESSORS_ONLN"
    NGINX_DEFAULT_OPT='--with-http_stub_status_module --with-stream --without-stream_access_module --with-cc-opt=-fno-common --with-ld-opt=-L/usr/pkg/lib\ -Wl,-R/usr/pkg/lib'
    MAKE=gmake
elif [ `uname -s` = "FreeBSD" ]; then
    NPROCESSORS_ONLN="NPROCESSORS_ONLN"
    NGINX_DEFAULT_OPT='--with-http_stub_status_module --with-stream --without-stream_access_module --with-cc-opt=-fno-common'
    MAKE=gmake
else
    NPROCESSORS_ONLN="_NPROCESSORS_ONLN"
    NGINX_DEFAULT_OPT='--with-http_stub_status_module --with-stream --without-stream_access_module --with-cc-opt=-fno-common'
    MAKE=make
fi

if [ -n "$BUILD_DYNAMIC_MODULE" ]; then
    BUILD_DIR='build_dynamic'
    NGINX_INSTALL_DIR=`pwd`'/build_dynamic/nginx'
    CONFIG_OPT="--enable-dynamic-module --with-build-dir=$BUILD_DIR"
else
    BUILD_DIR='build'
    NGINX_INSTALL_DIR=`pwd`'/build/nginx'
    CONFIG_OPT="--with-build-dir=$BUILD_DIR"
fi

if [ "$NGINX_CONFIG_OPT_ENV" != "" ]; then
    NGINX_CONFIG_OPT=$NGINX_CONFIG_OPT_ENV
else
    NGINX_CONFIG_OPT="--prefix=${NGINX_INSTALL_DIR} ${NGINX_DEFAULT_OPT}"
fi

if [ "$NUM_THREADS_ENV" != "" ]; then
    NUM_THREADS=$NUM_THREADS_ENV
else
    NUM_PROCESSORS=`getconf $NPROCESSORS_ONLN`
    if [ $NUM_PROCESSORS -gt 1 ]; then
        NUM_THREADS=$(expr $NUM_PROCESSORS / 2)
    else
        NUM_THREADS=1
    fi
fi

echo "NGINX_CONFIG_OPT=$NGINX_CONFIG_OPT"
echo "NUM_THREADS=$NUM_THREADS"

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
        tar xzf ${NGINX_SRC_VER}.tar.gz
    fi
    ln -snf ${NGINX_SRC_VER} nginx_src
    NGINX_SRC=`pwd`'/nginx_src'
    cd ..
fi

if [ -n "$OPENSSL_SRC_VERSION" ]; then
    cd ${BUILD_DIR}
    curl -sfL https://www.openssl.org/source/openssl-${OPENSSL_SRC_VERSION}.tar.gz -o openssl-${OPENSSL_SRC_VERSION}.tar.gz
    mkdir openssl-${OPENSSL_SRC_VERSION} && tar -xzf openssl-${OPENSSL_SRC_VERSION}.tar.gz -C openssl-${OPENSSL_SRC_VERSION} --strip-components 1
    rm openssl-${OPENSSL_SRC_VERSION}.tar.gz
    cd openssl-${OPENSSL_SRC_VERSION}
    ./config --prefix=/usr/local --shared zlib -fPIC >> /dev/null 2>&1
    OPENSSL_BUILD_OPT="--with-openssl-src=$BUILD_DIR/openssl-$OPENSSL_SRC_VERSION"
    cd ../..
else
    OPENSSL_BUILD_OPT=''
fi

echo "ngx_mruby configure ..."
./configure ${CONFIG_OPT} --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="${NGINX_CONFIG_OPT}" ${OPENSSL_BUILD_OPT} $@
echo "ngx_mruby configure ... Done"

echo "ngx_mruby building ..."
$MAKE NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
echo "ngx_mruby building ... Done"

echo "build.sh ... successful"

#sudo make install
