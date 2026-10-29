#!/bin/sh
# Starts and stops the services that test/t/cases/auto_ssl.rb needs (see
# "Testing the auto-ssl mrbgem" in docs/test/README.md):
#
# - Redis 7.4 on 127.0.0.1:6379, which the auto-ssl handlers of the tests
#   read and write;
# - Pebble, the ACME test server of Let's Encrypt, with its API on
#   127.0.0.1:14000 and its management API on 127.0.0.1:15000. It validates
#   http-01 challenges on port 18174 of the domain;
# - pebble-challtestsrv as the DNS server of Pebble, on 127.0.0.1:8053, which
#   answers every A query with 127.0.0.1 and no AAAA query;
# - the dehydrated ACME client, a release checked against its SHA-256.
#
# Usage: sh test/auto_ssl/deps.sh start DIR
#        sh test/auto_ssl/deps.sh stop
#
# start downloads dehydrated into DIR and checks its checksum, writes the
# configuration of Pebble there, copies the certificate of the CA that signed
# Pebble's HTTPS certificate (pebble.minica.pem) out of the Pebble image,
# starts the three containers and waits until they listen. The case finds the
# files through NGX_MRUBY_TEST_AUTO_SSL=DIR.
#
# The containers use the network AUTO_SSL_DOCKER_NETWORK (default: host), so
# that 127.0.0.1 is the same for them and for the test nginx. To run test.sh
# in a container, start that container first and set
# AUTO_SSL_DOCKER_NETWORK=container:NAME. The containers are named
# AUTO_SSL_CONTAINER_PREFIX-redis, -challtestsrv and -pebble (default prefix:
# ngx-mruby-auto-ssl); stop removes those three only.

set -eu

REDIS_IMAGE='redis:7.4.6@sha256:a9cc41d6d01da2aa26c219e4f99ecbeead955a7b656c1c499cce8922311b2514'
PEBBLE_IMAGE='ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199'
CHALLTESTSRV_IMAGE='ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b'
DEHYDRATED_VERSION='0.7.2'
DEHYDRATED_SHA256='7ea5a75bfcdf04bbb6ef88d03f89dec8101a2d3ea1dd467d8c42cbb0339ed5cb'

NETWORK=${AUTO_SSL_DOCKER_NETWORK:-host}
PREFIX=${AUTO_SSL_CONTAINER_PREFIX:-ngx-mruby-auto-ssl}
# The upper bound, in seconds, of the wait for each container.
LIMIT=60

usage() {
    echo "usage: sh $0 start DIR | stop" >&2
    exit 2
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

# wait_for_log NAME TEXT: waits until the log of the container NAME has TEXT.
wait_for_log() {
    i=0
    while [ "$i" -lt "$((LIMIT * 5))" ]; do
        if docker logs "$PREFIX-$1" 2>&1 | grep -qF "$2"; then
            echo "$PREFIX-$1: $2"
            return 0
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-$1")" != true ]; then
            docker logs "$PREFIX-$1" >&2 || true
            echo "$PREFIX-$1 stopped before its log had: $2" >&2
            return 1
        fi
        sleep 0.2
        i=$((i + 1))
    done
    docker logs "$PREFIX-$1" >&2 || true
    echo "$PREFIX-$1: no \"$2\" in its log after $LIMIT seconds" >&2
    return 1
}

stop() {
    for c in pebble challtestsrv redis; do
        if docker inspect "$PREFIX-$c" >/dev/null 2>&1; then
            docker rm -f "$PREFIX-$c" >/dev/null
            echo "removed $PREFIX-$c"
        fi
    done
}

start() {
    mkdir -p "$1"
    dir=$(cd "$1" && pwd)

    tarball="$dir/dehydrated-$DEHYDRATED_VERSION.tar.gz"
    curl -sfL -o "$tarball" "https://github.com/dehydrated-io/dehydrated/releases/download/v$DEHYDRATED_VERSION/dehydrated-$DEHYDRATED_VERSION.tar.gz"
    actual=$(sha256 "$tarball")
    if [ "$actual" != "$DEHYDRATED_SHA256" ]; then
        echo "dehydrated-$DEHYDRATED_VERSION.tar.gz: SHA-256 $actual, expected $DEHYDRATED_SHA256" >&2
        exit 1
    fi
    tar -xzf "$tarball" -C "$dir" --strip-components 1 "dehydrated-$DEHYDRATED_VERSION/dehydrated"
    chmod +x "$dir/dehydrated"
    rm -f "$tarball"
    echo "dehydrated $DEHYDRATED_VERSION in $dir/dehydrated (SHA-256 of the release checked)"

    # Pebble's own HTTPS certificate is the one in its image (test/certs/);
    # httpPort is the port where it validates http-01 challenges.
    cat > "$dir/pebble-config.json" <<'JSON'
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 18174,
    "tlsPort": 18175,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
JSON

    stop
    docker pull -q "$REDIS_IMAGE" >/dev/null
    docker pull -q "$CHALLTESTSRV_IMAGE" >/dev/null
    docker pull -q "$PEBBLE_IMAGE" >/dev/null

    id=$(docker create "$PEBBLE_IMAGE")
    docker cp "$id:/test/certs/pebble.minica.pem" "$dir/pebble.minica.pem" >/dev/null
    docker rm "$id" >/dev/null

    docker run -d --name "$PREFIX-redis" --network "$NETWORK" "$REDIS_IMAGE" \
        redis-server --bind 127.0.0.1 --port 6379 --save '' --appendonly no >/dev/null
    docker run -d --name "$PREFIX-challtestsrv" --network "$NETWORK" "$CHALLTESTSRV_IMAGE" \
        -defaultIPv4 127.0.0.1 -defaultIPv6 '' -dnsserver 127.0.0.1:8053 \
        -management 127.0.0.1:8055 -http01 '' -https01 '' -tlsalpn01 '' -doh '' >/dev/null
    # PEBBLE_VA_NOSLEEP: no random delay before a validation.
    # PEBBLE_WFE_NONCEREJECT=0: no random rejection of valid nonces.
    docker run -d --name "$PREFIX-pebble" --network "$NETWORK" \
        -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
        -v "$dir/pebble-config.json:/auto-ssl/pebble-config.json:ro" "$PEBBLE_IMAGE" \
        -config /auto-ssl/pebble-config.json -dnsserver 127.0.0.1:8053 >/dev/null

    wait_for_log redis 'Ready to accept connections'
    wait_for_log challtestsrv '127.0.0.1:8053'
    wait_for_log pebble 'Listening on: 127.0.0.1:14000'
    echo "NGX_MRUBY_TEST_AUTO_SSL=$dir"
}

case "${1:-}" in
    start)
        [ $# -eq 2 ] || usage
        start "$2"
        ;;
    stop)
        [ $# -eq 1 ] || usage
        stop
        ;;
    *)
        usage
        ;;
esac
