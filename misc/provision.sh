#/bin/sh

sudo apt-get update
sudo apt-get -y install build-essential rake bison git gperf automake m4 \
                autoconf libtool cmake pkg-config libcunit1-dev ragel \
                libpcre3-dev clang-format-6.0
sudo apt-get -y remove nano

sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-6.0 1000

git clone https://github.com/matsumotory/ngx_mruby
