#!/bin/sh

# Default install and test
#   download nginx into ./build/
#   build into ./build/nginx
#   test on ./build/nginx

set -e

. ./nginx_version

# OS specific configuration
NGINX_CC_OPT='-g -O0 -fno-common'
NGINX_LD_OPT=''
if [ `uname -s` = "NetBSD" ]; then
    NPROCESSORS_ONLN="NPROCESSORS_ONLN"
    NGINX_LD_OPT='-L/usr/pkg/lib -Wl,-R/usr/pkg/lib'
    MAKE=gmake
elif [ `uname -s` = "FreeBSD" ]; then
    NPROCESSORS_ONLN="NPROCESSORS_ONLN"
    MAKE=gmake
else
    NPROCESSORS_ONLN="_NPROCESSORS_ONLN"
    MAKE=make
fi

# Extra compiler and linker flags for nginx, which also compiles ngx_mruby,
# for example for the sanitizer build in CI:
#   NGINX_EXTRA_CC_OPT='-fsanitize=address,undefined -fno-omit-frame-pointer'
#   NGINX_EXTRA_LD_OPT='-fsanitize=address,undefined'
# mruby takes its extra flags from NGX_MRUBY_CFLAGS and NGX_MRUBY_LDFLAGS
# (see build_config.rb).
NGINX_CC_OPT="$NGINX_CC_OPT $NGINX_EXTRA_CC_OPT"
NGINX_LD_OPT="$NGINX_LD_OPT $NGINX_EXTRA_LD_OPT"

# The configure options are split again by the shell that make runs, so the
# spaces inside one option value are escaped.
escape_spaces() {
    printf '%s\n' "$1" | sed -e 's/^  *//' -e 's/  *$//' -e 's/  */\\ /g'
}
# The tests use these modules of nginx besides the default ones:
# http_auth_request lets a test run a phase handler of nginx that waits for a
# subrequest after an mruby handler (test/t/cases/request_body_later.rb).
NGINX_DEFAULT_OPT="--with-debug --with-http_stub_status_module --with-http_ssl_module --with-http_auth_request_module --with-cc-opt=`escape_spaces "$NGINX_CC_OPT"`"
if [ -n "`escape_spaces "$NGINX_LD_OPT"`" ]; then
    NGINX_DEFAULT_OPT="$NGINX_DEFAULT_OPT --with-ld-opt=`escape_spaces "$NGINX_LD_OPT"`"
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
export NGINX_INSTALL_DIR # for test/t/ngx_mruby.rb

# Same encoding as nginx's own nginx_version macro (1.11.5 -> 1011005), so
# that versions are compared as a whole instead of minor and patch separately.
NGINX_SRC_VERSION_NUM=$((NGINX_SRC_MAJOR * 1000000 + NGINX_SRC_MINOR * 1000 + NGINX_SRC_PATCH))

if [ "$NGINX_SRC_VERSION_NUM" -ge 1011005 ]; then
    NGINX_CONFIG_OPT="--prefix=${NGINX_INSTALL_DIR} ${NGINX_DEFAULT_OPT} --with-stream"
elif [ "$NGINX_SRC_VERSION_NUM" -ge 1009006 ]; then
    NGINX_CONFIG_OPT="--prefix=${NGINX_INSTALL_DIR} ${NGINX_DEFAULT_OPT} --with-stream --without-stream_access_module"
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

export NGX_MRUBY_CFLAGS="-DMRB_GC_STRESS $NGX_MRUBY_CFLAGS"

if [ "$ONLY_BUILD_NGX_MRUBY" = "" ]; then

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

  echo "ngx_mruby configure ..."
  ./configure ${CONFIG_OPT} --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="${NGINX_CONFIG_OPT}" $@
  echo "ngx_mruby configure ... Done"
fi

echo "ngx_mruby building ..."
$MAKE NUM_THREADS=$NUM_THREADS -j $NUM_THREADS
echo "ngx_mruby building ... Done"

echo "ngx_mruby testing ..."
$MAKE install
# TEST_SH_SKIP_TESTS=1 stops after the build and the install, before the test
# configuration is written and nginx is started: test/nginx-tests/run.sh
# builds nginx with ngx_mruby this way and runs nginx's own test suite on it.
if [ -n "$TEST_SH_SKIP_TESTS" ]; then
    echo "test.sh ... built and installed to ${NGINX_INSTALL_DIR}; tests skipped (TEST_SH_SKIP_TESTS)"
    exit 0
fi

# test.sh stops only the nginx processes that it started, by their pid (see
# "Stopping nginx" in docs/test/README.md). It never signals an nginx by its
# name, so the nginx processes of other checkouts and of other users stay.

# The upper bound, in seconds, of each stop of an nginx below.
: ${NGINX_STOPTIME:=60}

# True when process $1 is gone, or has ended and waits to be collected (a
# zombie): kill -0 still succeeds for a zombie.
nginx_ended() {
    nginx_stat=`ps -o stat= -p "$1" 2>/dev/null | tr -d ' '` || nginx_stat=
    case "$nginx_stat" in
        ''|Z*) return 0 ;;
        *) return 1 ;;
    esac
}

# True when process $1 runs the nginx of this build directory: its command
# line contains the absolute path of sbin/nginx (also under valgrind). The
# shell may have collected an nginx that ended, and its pid may then belong
# to another process, so test.sh checks this before each signal. -ww keeps
# ps from cutting the line at COLUMNS.
nginx_is_ours() {
    ps -ww -o args= -p "$1" 2>/dev/null | grep -F "${NGINX_INSTALL_DIR}/sbin/nginx" >/dev/null
}

# Sends SIGTERM to the nginx with pid $1 and waits until it has ended. A
# single nginx process (master_process off) checks for the signal only after
# it has handled its events, so a SIGTERM that arrives after that check and
# before it waits for events again stays unseen until the next event, which
# may never come (ngx_single_process_cycle). The signal is therefore sent
# again 1, 3, 7, 15 and 31 seconds after the first one, as the master
# process of nginx sends it again to its workers with a delay that doubles.
# After NGINX_STOPTIME seconds the process gets SIGKILL and the stop fails.
# The times are counted in rounds of "sleep 0.1" and a ps, so the real times
# are somewhat longer. A pid that no longer runs this build's nginx counts as
# ended and gets no signal.
stop_nginx() {
    stop_pid=$1
    stop_signals=0
    stop_ticks=0
    stop_next=10
    stop_step=10
    if nginx_is_ours "$stop_pid"; then
        kill -TERM "$stop_pid" 2>/dev/null || true
        stop_signals=1
    fi
    while ! nginx_ended "$stop_pid" && nginx_is_ours "$stop_pid"; do
        if [ "$stop_ticks" -ge $((NGINX_STOPTIME * 10)) ]; then
            if nginx_is_ours "$stop_pid"; then kill -KILL "$stop_pid" 2>/dev/null || true; fi
            echo "test.sh: nginx (pid $stop_pid) did not end within ${NGINX_STOPTIME} seconds (NGINX_STOPTIME) after $stop_signals SIGTERM; sent SIGKILL"
            return 1
        fi
        sleep 0.1
        stop_ticks=$((stop_ticks + 1))
        if [ "$stop_ticks" -eq "$stop_next" ] && nginx_is_ours "$stop_pid"; then
            kill -TERM "$stop_pid" 2>/dev/null || true
            stop_signals=$((stop_signals + 1))
            stop_step=$((stop_step * 2))
            stop_next=$((stop_next + stop_step))
        fi
    done
    if [ "$stop_signals" -eq 0 ]; then
        echo "test.sh: nginx (pid $stop_pid) had ended before the stop; no signal sent"
    else
        echo "test.sh: nginx (pid $stop_pid) ended within about $((stop_ticks / 10)).$((stop_ticks % 10)) seconds of the first SIGTERM; SIGTERM sent $stop_signals times"
    fi
}

# An earlier run of test.sh that was killed before it could stop its nginx
# leaves that nginx running, with its pid in logs/nginx.pid. Stop it if the
# process still runs the nginx of this build directory; the pid may belong to
# another process by now.
if [ -s ${NGINX_INSTALL_DIR}/logs/nginx.pid ]; then
    old_pid=`cat ${NGINX_INSTALL_DIR}/logs/nginx.pid`
    if nginx_is_ours "$old_pid"; then
        echo "test.sh: stopping the nginx (pid $old_pid) that an earlier run left running"
        stop_nginx "$old_pid"
    elif ! nginx_ended "$old_pid"; then
        echo "test.sh: logs/nginx.pid names pid $old_pid, which does not run ${NGINX_INSTALL_DIR}/sbin/nginx; left running"
    fi
fi
sed -e "s|__NGXDOCROOT__|${NGINX_INSTALL_DIR}/html/|g" test/conf/nginx.conf > ${NGINX_INSTALL_DIR}/conf/nginx.conf
rm -rf ${NGINX_INSTALL_DIR}/conf/conf.d
mkdir -p ${NGINX_INSTALL_DIR}/conf/conf.d/stream
for f in test/conf/conf.d/*.conf test/conf/conf.d/stream/*.conf; do
    [ -e "$f" ] || continue
    case "$f" in */stream/*) d=${NGINX_INSTALL_DIR}/conf/conf.d/stream ;; *) d=${NGINX_INSTALL_DIR}/conf/conf.d ;; esac
    sed -e "s|__NGXDOCROOT__|${NGINX_INSTALL_DIR}/html/|g" "$f" > "$d/$(basename "$f")"
done
cd ${NGINX_INSTALL_DIR}/html && sh -c 'yes "" | openssl req -new -days 365 -x509 -nodes -keyout localhost.key -out localhost.crt' && sh -c 'yes "" | openssl req -new -days 1 -x509 -nodes -keyout dummy.key -out dummy.crt' && cd -

if [ "$NGINX_SRC_VERSION_NUM" -ge 1009006 ]; then
  cat test/conf/nginx.stream.conf >> ${NGINX_INSTALL_DIR}/conf/nginx.conf
fi

if [ -n "$BUILD_DYNAMIC_MODULE" ]; then
    sed -e "s|build/nginx|build_dynamic/nginx|g" ${NGINX_INSTALL_DIR}/conf/nginx.conf | tee ${NGINX_INSTALL_DIR}/conf/nginx.conf.tmp
    echo "load_module modules/ngx_http_mruby_module.so;" > ${NGINX_INSTALL_DIR}/conf/nginx.conf
    cat ${NGINX_INSTALL_DIR}/conf/nginx.conf.tmp >> ${NGINX_INSTALL_DIR}/conf/nginx.conf
    for f in ${NGINX_INSTALL_DIR}/conf/conf.d/*.conf ${NGINX_INSTALL_DIR}/conf/conf.d/stream/*.conf; do
        [ -e "$f" ] || continue
        sed -e "s|build/nginx|build_dynamic/nginx|g" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    done
fi

cp -pr test/html/* ${NGINX_INSTALL_DIR}/html/.
sed -e "s|__NGXDOCROOT__|${NGINX_INSTALL_DIR}/html/|g" test/html/set_ssl_cert_and_key.rb > ${NGINX_INSTALL_DIR}/html/set_ssl_cert_and_key.rb

for f in error.log access.log stderr.log
do
    if [ -e ${NGINX_INSTALL_DIR}/logs/${f} ]; then
        touch ${NGINX_INSTALL_DIR}/logs/${f}.bak 
        cat ${NGINX_INSTALL_DIR}/logs/${f} >> ${NGINX_INSTALL_DIR}/logs/${f}.bak
        cp /dev/null ${NGINX_INSTALL_DIR}/logs/${f}
    fi
done

: ${NGINX_RUNNER:=exec}
# The upper bound, in seconds, of each wait for the ports of the test nginx
# below; test.sh goes on as soon as nginx accepts connections. See "Waiting
# for nginx to listen" in docs/test/README.md for what the value is based on.
: ${NGINX_HEATTIME:=60}

# The ports to wait for are those of the listen directives of the http {}
# configuration (see test/t/cases/_wait_for_listen.rb). They must be free
# before nginx starts, so that the wait cannot take another process for it.
ruby test/t/cases/_wait_for_listen.rb free ${NGINX_HEATTIME} test/conf/nginx.conf test/conf/conf.d/*.conf

echo "====================================="
echo ""
echo "ngx_mruby starting and logging"
echo ""
echo "====================================="
echo ""
echo ""
${NGINX_RUNNER} ${NGINX_INSTALL_DIR}/sbin/nginx &
nginx_pid=$!
# Stop nginx when test.sh exits, also after a failure or a signal, and keep
# the exit status of test.sh unless the stop itself fails. The exit status of
# nginx is printed and does not change it.
on_exit() {
    exit_status=$1
    trap - EXIT
    if stop_nginx "$nginx_pid"; then
        nginx_status=0
        wait "$nginx_pid" || nginx_status=$?
        echo "test.sh: nginx (pid $nginx_pid) exit status $nginx_status"
    else
        wait "$nginx_pid" || true
        exit_status=1
    fi
    exit "$exit_status"
}
trap 'on_exit $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
echo ""
echo ""
ruby test/t/cases/_wait_for_listen.rb listen ${NGINX_HEATTIME} $nginx_pid test/conf/nginx.conf test/conf/conf.d/*.conf
./mruby/build/test/bin/mruby ./test/t/ngx_mruby.rb 2> ${NGINX_INSTALL_DIR}/logs/stderr.log
for f in test/t/cases/*.rb; do
    [ -e "$f" ] || continue
    case "$f" in */_*) continue ;; esac
    echo "ngx_mruby testing case: $f"
    cat test/t/cases/_prelude.rb "$f" > ${NGINX_INSTALL_DIR}/logs/case.rb
    ./mruby/build/test/bin/mruby ${NGINX_INSTALL_DIR}/logs/case.rb 2>> ${NGINX_INSTALL_DIR}/logs/stderr.log
done
echo "ngx_mruby testing ... Done"

echo "test.sh ... successful"
