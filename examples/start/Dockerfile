# nginx with ngx_mruby, built from this checkout of the repository
# (examples/start/README.md). compose.yaml builds it with the top of the
# repository as the context; Dockerfile.dockerignore keeps build output and
# the site's packages out of that context.
FROM ubuntu:24.04

# The build requirements of docs/install/README.md, and curl for the
# health check of compose.yaml.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential bison ca-certificates curl git gperf rake ruby wget \
      libpcre3-dev libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . /usr/local/src/ngx_mruby
WORKDIR /usr/local/src/ngx_mruby

# build.sh downloads the nginx version of ./nginx_version from nginx.org,
# builds mruby with the gems of build_config.rb at the commits of
# build_config.rb.lock, and builds nginx with ngx_mruby as a static module.
RUN NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx --with-stream --without-stream_access_module' sh build.sh \
 && make install

EXPOSE 8080
CMD ["/usr/local/nginx/sbin/nginx", "-c", "/example/nginx.conf", "-g", "daemon off;"]
