#/bin/sh

echo '
export CXX="g++-4.9"
export CC="gcc-4.9"
export LD="gcc-4.9"
' | sudo tee /etc/profile.d/env.sh

grep "^deb http://dk.archive.ubuntu.com/ubuntu/ xenial main" /etc/apt/sources.list || echo "deb http://dk.archive.ubuntu.com/ubuntu/ xenial main" | sudo tee -a /etc/apt/sources.list
grep "^deb http://dk.archive.ubuntu.com/ubuntu/ xenial universe" /etc/apt/sources.list || echo "deb http://dk.archive.ubuntu.com/ubuntu/ xenial universe" | sudo tee -a /etc/apt/sources.list
echo "libssl1.1 libraries/restart-without-asking boolean true" | sudo debconf-set-selections

sudo apt-get update
sudo apt-get -y install build-essential rake bison git gperf automake m4 \
                autoconf libtool cmake pkg-config libcunit1-dev ragel \
                libpcre3-dev clang-format-6.0 g++-4.9 libstdc++-4.9-dev
sudo apt-get -y remove nano

sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-6.0 1000

default_openssl_version=1.1.1
if [ "${OPENSSL_SRC_VERSION}" == "" ]; then export OPENSSL_SRC_VERSION=${default_openssl_version}; fi
curl -sfL https://www.openssl.org/source/openssl-${OPENSSL_SRC_VERSION}-latest.tar.gz -o openssl-${OPENSSL_SRC_VERSION}.tar.gz
mkdir openssl-${OPENSSL_SRC_VERSION} && tar -xzf openssl-${OPENSSL_SRC_VERSION}.tar.gz -C openssl-${OPENSSL_SRC_VERSION} --strip-components 1
rm openssl-${OPENSSL_SRC_VERSION}.tar.gz
cd openssl-${OPENSSL_SRC_VERSION}
./config --prefix=/usr/local --shared zlib -fPIC
make
sudo make install
sudo ldconfig /usr/local/lib
cd -
openssl version

git clone https://github.com/matsumotory/ngx_mruby
