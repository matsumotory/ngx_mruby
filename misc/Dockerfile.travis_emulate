FROM ubuntu:14.04
## emulates Travis.ci environment
# Usage:
#   build:
#     docker build -f misc/Dockerfile.travis_emulate -t ngx_mruby:branch_name .
#   run:
#     docker run -it ngx_mruby:branch_name
#       or,
#     docker run -it -v `pwd`:/ngx_mruby ngx_mruby:branch_name

RUN apt-get update
RUN apt-get install -y bash-completion apt-file software-properties-common && apt-file update
RUN add-apt-repository --yes ppa:ubuntu-toolchain-r/test && apt-get update
RUN apt-get install -y \
  build-essential wget libpcre3-dev psmisc \
  rake bison git gperf zlib1g-dev g++-4.9 libstdc++-4.9-dev \
  vim tmux

ENV CXX "g++-4.9"
ENV CC "gcc-4.9"

RUN curl -L https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz -o openssl-1.0.2.tar.gz && \
  tar -xzf openssl-1.0.2.tar.gz && \
  rm openssl-1.0.2.tar.gz && \
  cd openssl-1.0.2* && \
  ./config --prefix=/usr/local --shared zlib -fPIC enable-tlsext && \
  make && \
  sudo make install && \
  sudo ldconfig /usr/local/lib

## Add or -v `pwd`:/ngx_mruby
ADD . /ngx_mruby

WORKDIR /ngx_mruby
CMD ["/bin/bash"]

