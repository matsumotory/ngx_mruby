#/bin/sh

sudo apt-get update
sudo apt-get -y install build-essential rake bison git gperf automake m4 \
                autoconf libtool cmake pkg-config libcunit1-dev ragel libpcre3-dev

git clone https://github.com/matsumotory/ngx_mruby
