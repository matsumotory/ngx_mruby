#!/bin/sh
#
# Build nginx with ngx_mruby as a static module with release-like options, in
# a copy of the sources. The memory soak test (test/soak/run.sh) and the
# performance comparison (test/perf/run.sh, test/perf/compare.sh) build with
# this script; see docs/test/README.md.
#
#   sh test/build_release.sh SOURCE_DIR BUILD_DIR
#
# SOURCE_DIR is the checkout to build: the repository root, or another
# checkout such as the base of a pull request. The build files come from
# SOURCE_DIR as well (build.sh, configure, build_config.rb, ...), so a
# checkout is built the way it builds itself; only this script and its
# options come from the checkout that runs it. BUILD_DIR receives:
#
#   BUILD_DIR/tree          copy of the sources; the nginx source is in BUILD_DIR/tree/build
#   BUILD_DIR/nginx         nginx installed by `make install`
#   BUILD_DIR/build_stamp   the untracked inputs of the last build
#
# Environment:
#   RELEASE_CC_OPT    extra options for the compiler of nginx and ngx_mruby,
#                     separated by spaces. The soak build passes
#                     -DNGX_MRUBY_DEBUG_STATS; the perf build passes none.
#   NGX_MRUBY_CFLAGS  extra options for the compiler of mruby (as with test.sh)
#   RELEASE_GEM_LOCK  a build_config.rb.lock: the third-party gems are built at
#                     the commits it records. Without it, rake clones the
#                     default branch of each gem on the first build and records
#                     the commits in BUILD_DIR/tree/build_config.rb.lock.
#   NUM_THREADS_ENV   build parallelism (passed to build.sh)
#
# nginx and ngx_mruby are compiled with -g -O2 -fno-common and
# RELEASE_CC_OPT, without --with-debug. mruby is compiled with the flags of
# its gcc toolchain (-g -O3) and NGX_MRUBY_CFLAGS, without MRB_GC_STRESS.
#
# Why build.sh and not test.sh: test.sh always adds -DMRB_GC_STRESS, -O0 and
# --with-debug, and kills every running nginx. build.sh takes the nginx
# configure options from NGINX_CONFIG_OPT_ENV and adds no flags of its own,
# so this script sets its options without changing either script.
#
# Why a copy of the sources: configure writes Makefile, config and
# mrbgems_config into the directory it runs in, and mruby builds into
# mruby/build. Running build.sh in the repository root would replace the
# files that `ONLY_BUILD_NGX_MRUBY=1 sh test.sh` reuses, and builds with
# different options would share one mruby build. build.sh therefore runs in
# BUILD_DIR/tree, and each kind of build has a BUILD_DIR of its own.
#
# Some inputs of the build are not tracked by make and rake, so the script
# records them in BUILD_DIR/build_stamp and builds mruby and nginx from
# scratch when they change (see the comment at the stamp below). For a change
# that the stamp does not cover, `rm -rf BUILD_DIR` resets the build.

set -e

if [ $# -ne 2 ]; then
    echo "usage: sh test/build_release.sh SOURCE_DIR BUILD_DIR" >&2
    exit 2
fi
SRC=$(cd "$1" && pwd)
mkdir -p "$2"
OUT=$(cd "$2" && pwd)
TREE="$OUT/tree"
if [ -n "$RELEASE_GEM_LOCK" ]; then
    RELEASE_GEM_LOCK=$(cd "$(dirname "$RELEASE_GEM_LOCK")" && pwd)/$(basename "$RELEASE_GEM_LOCK")
    gem_lock=$(cksum < "$RELEASE_GEM_LOCK")
else
    gem_lock=none
fi
cd "$SRC"

# nginx's configure splits --with-cc-opt again in the shell that make runs,
# so the spaces are escaped (as test.sh does). RELEASE_CC_OPT is a list of
# options and is split on purpose.
NGINX_CC_OPT='-g\ -O2\ -fno-common'
for opt in $RELEASE_CC_OPT; do
    NGINX_CC_OPT="$NGINX_CC_OPT\\ $opt"
done
NGINX_CONFIG_OPT_ENV="--prefix=$OUT/nginx --with-http_stub_status_module --with-cc-opt=$NGINX_CC_OPT"
export NGINX_CONFIG_OPT_ENV
# build_config.rb passes NGX_MRUBY_CFLAGS to the mruby build.
export NGX_MRUBY_CFLAGS
TOP_FILES="configure config.in Makefile.in build.sh build_config.rb nginx_version"

# The stamp lists the inputs of the build that make and rake do not track:
# - The mruby tree. test.sh drops a stale mruby build through .mruby_version
#   (Makefile.in), which needs .git in the build directory, and the copy has
#   none. mruby archives with `ar rs`, so the objects of removed or renamed
#   sources would stay in libmruby.a. The tree id comes from git when
#   SOURCE_DIR is the top of a git work tree (it does not see uncommitted
#   changes), else from a checksum of the files. mruby/build and mruby/bin
#   are build output (of test.sh) and are left out of both.
# - The file names under mrbgems/, for the same reason.
# - The top-level build files: build_config.rb (a dropped gem stays in
#   libmruby.a as well), config.in, configure and build.sh (the sources and
#   options of nginx's configure), Makefile.in and nginx_version.
# - NGX_MRUBY_CFLAGS: rake does not rebuild mruby when only they change.
# - The nginx options, RELEASE_CC_OPT included. nginx's configure runs only
#   when objs/Makefile is missing, so later runs would keep the options of
#   the first one.
# - The gem lock given in RELEASE_GEM_LOCK.
# When the stamp differs from that of the last build, the mruby build (with
# the gem clones), the gem lock file and nginx's objs/ are removed, which
# makes the next steps build both from scratch, as on a fresh checkout. The
# downloaded nginx source is kept.
mruby_tree=
if top=$(git -C "$SRC" rev-parse --show-toplevel 2>/dev/null) &&
    [ "$(cd "$top" && pwd -P)" = "$(pwd -P)" ]; then
    mruby_tree=$(git -C "$SRC" rev-parse -q --verify HEAD:mruby 2>/dev/null) || mruby_tree=
fi
if [ -z "$mruby_tree" ]; then
    mruby_tree=$(find mruby \( -path mruby/build -o -path mruby/bin \) -prune -o -type f -exec cksum {} + | LC_ALL=C sort | cksum)
fi
# TOP_FILES is a list of names and is split on purpose.
stamp=$(
    printf 'mruby: %s\n' "$mruby_tree"
    printf 'mrbgems: %s\n' "$(find mrbgems -type f | LC_ALL=C sort | cksum)"
    cksum $TOP_FILES
    printf 'NGX_MRUBY_CFLAGS: %s\n' "$NGX_MRUBY_CFLAGS"
    printf 'NGINX_CONFIG_OPT_ENV: %s\n' "$NGINX_CONFIG_OPT_ENV"
    printf 'gem lock: %s\n' "$gem_lock"
)
mkdir -p "$TREE"
if [ "$(cat "$OUT/build_stamp" 2>/dev/null)" != "$stamp" ]; then
    if [ -e "$OUT/build_stamp" ]; then
        echo "build_release.sh: the build inputs changed; building mruby and nginx from scratch"
    fi
    rm -rf "$TREE/mruby/build" "$TREE/build_config.rb.lock" "$TREE"/build/*/objs
    printf '%s\n' "$stamp" > "$OUT/build_stamp"
fi
if [ -n "$RELEASE_GEM_LOCK" ]; then
    cp "$RELEASE_GEM_LOCK" "$TREE/build_config.rb.lock"
fi

# Bring the copy up to date with SOURCE_DIR: the top-level build files and
# src/, mrbgems/, dependence/ and mruby/ (without mruby/build and mruby/bin,
# the build output of test.sh).
#
# - A file is written only when its content differs, so that make and rake
#   rebuild what changed and nothing else. The modification time of a
#   written file is the time of the copy, not that of SOURCE_DIR: a checkout
#   made with git archive or git worktree can have files older than the
#   objects of the last build, and make would not rebuild them.
# - An existing file is overwritten in place, not removed and created again.
#   On a case-insensitive file system shared with a container (Docker
#   Desktop on macOS), rake looks up mruby's Rakefile as "rakefile", and
#   after the file was removed and created again in the same container,
#   loading it failed with a LoadError.
# - Files and directories that no longer exist in SOURCE_DIR are removed.
# - make does not see the headers in src/ and dependence/ as dependencies
#   (AGENTS.md), so when one of them changed, the .c files there are touched.
ruby - "$SRC" "$TREE" $TOP_FILES <<'RUBY'
require 'fileutils'

src_root, dst_root, *top_files = ARGV
roots = top_files + %w[src mrbgems dependence mruby]
skip = %w[mruby/build mruby/bin]

# Yields each entry under root/rel, rel first; does not descend into a
# directory that the block removed.
walk = lambda do |root, rel, &block|
  path = File.join(root, rel)
  st = File.lstat(path)
  block.call(rel, st)
  next unless st.directory? && File.directory?(path)

  Dir.children(path).sort.each do |name|
    child = File.join(rel, name)
    walk.call(root, child, &block) unless skip.include?(child)
  end
end

source = {}
roots.each { |r| walk.call(src_root, r) { |rel, st| source[rel] = st } }

written = []
source.each do |rel, st|
  from = File.join(src_root, rel)
  to = File.join(dst_root, rel)
  have = File.lstat(to) rescue nil
  if st.directory?
    FileUtils.rm_rf(to) if have && !have.directory?
    FileUtils.mkdir_p(to)
  elsif st.symlink?
    next if have&.symlink? && File.readlink(to) == File.readlink(from)

    FileUtils.rm_rf(to)
    File.symlink(File.readlink(from), to)
    written << rel
  else
    next if have&.file? && have.size == st.size && FileUtils.compare_file(from, to)

    FileUtils.rm_rf(to) if have && !have.file?
    File.open(to, File::WRONLY | File::CREAT | File::TRUNC | File::BINARY) do |out|
      File.open(from, 'rb') { |input| IO.copy_stream(input, out) }
    end
    File.chmod(st.mode & 0o7777, to)
    written << rel
  end
end

removed = 0
roots.each do |r|
  next unless File.exist?(File.join(dst_root, r)) || File.symlink?(File.join(dst_root, r))

  walk.call(dst_root, r) do |rel, _st|
    next if source.key?(rel)

    FileUtils.rm_rf(File.join(dst_root, rel))
    removed += 1
  end
end

if written.any? { |rel| rel.match?(%r{\A(src|dependence)/.*\.h\z}) }
  Dir.glob(File.join(dst_root, '{src,dependence}', '**', '*.c')).each { |c| FileUtils.touch(c) }
end

puts "build_release.sh: #{written.size} files written, #{removed} removed in #{dst_root}"
RUBY

# build.sh also reads these. The release build is always a static module,
# built from its own nginx source and the system OpenSSL. (The CI workflow
# sets OPENSSL_SRC_VERSION for every job.)
unset BUILD_DYNAMIC_MODULE NGINX_SRC_ENV OPENSSL_SRC_VERSION

cd "$TREE"
sh build.sh
make install
