ngx_mruby test uses mruby test.
ngx_mruby test is very earlier and experimental version. 

Welcome pull-request!
## Add test
##### Add location config to ``test/conf/nginx.conf``
```nginx
# Nginx.hello test
location /mruby {
    mruby_content_handler build/nginx/html/unified_hello.rb cache;
}
```
##### Add hook script into ``test/html/`` if you need the script for location config
```ruby
# test/htdocs/unified_hello.rb
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```
##### Add test code to ``test/t/ngx_mruby.rb``
```ruby
assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby/0.0.1 world!', res["body"]
end
```

## Add a test as a fragment and a case file

Instead of editing `test/conf/nginx.conf` and `test/t/ngx_mruby.rb`, a test
can live in files of its own:

- `test/conf/conf.d/<name>.conf`: a fragment included at the end of the
  `http {}` block. It holds its own `server {}` on a port of its own (18110
  and up; 18116 is taken by the second nginx that
  `test/t/cases/_second_instance.rb` starts). Fragments for `stream {}` go
  to `test/conf/conf.d/stream/` (ports 12353 and up; 12357 is taken by the
  second nginx).
- `test/t/cases/<name>.rb`: a test file run after `test/t/ngx_mruby.rb`,
  with `test/t/cases/_prelude.rb` prepended. The prelude defines `base`,
  `base_ssl`, `http_host`, `html_path`, `nginx_t` (runs `nginx -t` on a
  generated configuration), `tcp_client` and `second_instance`. It starts
  with `SimpleTest.new` and ends with `t.report`. Files whose name starts
  with `_` are helpers and are not run by test.sh; `_tcp_client.rb`,
  `_filter_connection_client.rb` and `_second_instance.rb` are CRuby
  scripts that the prelude helpers run with `ruby`.
- Hook scripts go to `test/html/` as before; the fragment refers to them as
  `build/nginx/html/<name>.rb`.

`test.sh` copies the fragments into the built nginx's `conf/conf.d/` with the
same substitutions as `nginx.conf`, and runs every case file in turn. A
failing case makes `test.sh` exit non-zero, like a failing assertion in
`test/t/ngx_mruby.rb`.

A case that starts nginx itself (`nginx_t`, `second_instance`) also runs in
the sanitizer cell of CI, where LeakSanitizer appends its report to the
output of a process that leaked and changes that process's exit status. Run
such a case once with the sanitizer build (see "Running the tests under
AddressSanitizer and UndefinedBehaviorSanitizer" below) before opening the
PR. `nginx_t` turns leak detection off for its `nginx -t` run, because
`nginx -t` returns without freeing the configuration it read, so every
allocation of nginx itself would be reported. The stream-only test at the end
of `test/t/ngx_mruby.rb` does the same for the `nginx -s quit` that stops the
nginx it started: that process also returns from nginx's `main()` without
freeing the pool that `main()` creates first, and its report would go to the
test runner's `stderr.log`. `second_instance` returns the
first sanitizer line of the second nginx's `error.log` as `sanitizer`, and
the cases print that log when the line is set.

## Required status check

`.github/workflows/test.yml` runs on pull requests to `master`, `next` and
`v*.x`, on pushes to those branches and to `v*` tags, and on "Run workflow".
Its `ci-ok` job is the status check that rulesets require: it fails unless
every job that it lists in `needs` succeeded. These are every job of the
`build` matrix and the `files` job, and on `next` also the `soak` job.

### Files that do not belong in the repository

The `files` job runs `test/check_added_files.sh BASE HEAD TIP`. The script
checks two lists of files:

- the files that the change adds: the paths that `HEAD` has and `BASE` does
  not have (`git diff --no-renames --diff-filter=A`, so a file that is renamed
  or moved counts as added at its new path);
- the files that its commits add: each commit from `TIP` back along first
  parents to `BASE` (`git log --first-parent BASE..TIP`), compared with its
  first parent. A file that one commit adds and a later commit removes stays
  in the history after the merge, so it is checked as well.

A file of either list fails with exit status 1 when it matches a pattern of
`test/forbidden_paths.txt`: a session directory or the local settings of an AI
coding agent under `.claude/` (everything there except
`.claude/settings.json`, `.claude/commands/` and `.claude/skills/`, which also
fail below another `.claude/`), a build directory at the top (`build/`,
`build_dynamic/`, `build_soak/`, `build_perf/`) or `mruby/build/`, a file
that `./configure` or the Makefile writes at the top (`Makefile`, `config`,
`config.status`, `autom4te.cache/`, `mrbgems_config`, `.mruby_version`, the
`.openssl_*_done` files), `.vagrant/`, a tag file of GNU Global or ctags, a
`.log` file, `.env` or `.env.*`, private key material, an editor or OS
leftover, `node_modules/`, `__pycache__/` or a `.pyc` file, or a core dump. A
file of the first list also fails when it is empty (0 bytes), unless its name
is `.gitkeep` or `.keep`. Both lists include submodule entries (gitlinks),
whatever the git configuration or `.gitmodules` says about ignoring
submodules.

The script prints each failing path with the pattern and its line in the
pattern file, or with "empty file", and with the commit that added it. When
every file passes, it prints how many files it checked and exits 0. It exits
2 when the pattern file is missing, a pattern is invalid, a revision is not
in the repository, the repository is a shallow clone or a git command fails.
It reads only the pattern file and the git repository.

The commits follow first parents only. A merge commit among them is compared
with its first parent, so the files that its second parent brings in are
checked at the paths they have in the repository, and the commits of the
second parent are not checked one by one. This keeps out the squashed commit
of a subtree merge (`./update-mruby-subtree`), whose paths lack the `mruby/`
prefix. It also means that the check does not see a file that a commit of a
merged side branch adds and a later commit of that side branch removes.

For a pull request, the job checks out the merge commit of the pull request
with the whole history (`fetch-depth: 0`). It compares the merge commit with
its first parent, the base branch that the pull request was merged into, and
checks the commits from the head of the pull request (the second parent) back
to that base. So a pull request whose branch is behind its base is not blamed
for the files that the base removed in the meantime. For a push to a branch,
the job compares the previous tip of the branch (`github.event.before`) with
the pushed commit, and checks the commits between them. A tag push, a push
that creates a branch and a manual run have nothing to compare, and the job
passes. A pull request that changes the script or the pattern file is checked
with its own version of them, so the review of the pull request covers that
change.

`test/forbidden_paths.txt` holds one POSIX extended regular expression (as
`grep -E` reads it) per line, matched against the path from the top of the
repository. A line that starts with `!` is an exception, and the last line
that a path matches decides, as in `.gitignore`: `.claude/skills/a/SKILL.md`
matches `(^|/)\.claude/` and then the exception `!(^|/)\.claude/skills/`, so
it passes, while `.claude/skills/a/.DS_Store` also matches `(^|/)\.DS_Store$`
further down and fails. Empty lines and lines that start with `#` are
comments. The patterns must be generic: no names of other projects, people or
hosts.

To run the check before opening a pull request, commit the change and compare
it with the base branch (`origin/next` for a change to `next`). With two
arguments, the script also checks the commits from `HEAD` back to the base.
It needs the whole history, so run it in a clone that is not shallow:

```console
$ git fetch origin master
$ sh test/check_added_files.sh origin/master HEAD
check_added_files.sh: 2 added file(s) checked between origin/master and HEAD and in the 2 commit(s) of origin/master..HEAD, none forbidden or empty
```

When a file fails, remove it from the change (`git rm --cached <path>` keeps
it on disk), or, if it belongs in the repository, change
`test/forbidden_paths.txt` (for an empty file, the script) in the same pull
request and say why in its description. A file that a commit adds and a later
commit removes stays in the history: remove it from the commit that added it
(for example with `git rebase -i`), or squash the commits.

## Testing
##### build nginx into ``./build/nginx`` and test on ``./build/nginx``
```
sh test.sh
```

If you want to run with valgrind, set the environment variables `NGINX_RUNNER` and `NGINX_HEATTIME`.

```console
$ NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh
```

## Running the tests under AddressSanitizer and UndefinedBehaviorSanitizer

CI builds one matrix cell with `-fsanitize=address,undefined`. To run the
same build locally (Linux, gcc or clang):

```console
$ sudo sysctl -w vm.mmap_rnd_bits=28     # ASan and the kernel's high-entropy ASLR do not mix
$ export NGINX_EXTRA_CC_OPT="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGINX_EXTRA_LD_OPT="-fsanitize=address,undefined"
$ export NGX_MRUBY_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGX_MRUBY_LDFLAGS="-fsanitize=address,undefined"
$ export ASAN_OPTIONS="detect_leaks=1"
$ export LSAN_OPTIONS="suppressions=$PWD/test/lsan.supp"
$ export UBSAN_OPTIONS="print_stacktrace=1:suppressions=$PWD/test/ubsan.supp"
$ NGINX_RUNNER=exec sh test.sh
$ grep -E 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|LeakSanitizer' build/nginx/logs/error.log
```

`NGINX_EXTRA_CC_OPT` and `NGINX_EXTRA_LD_OPT` are appended to nginx's
`--with-cc-opt` and `--with-ld-opt`; `NGX_MRUBY_CFLAGS` and `NGX_MRUBY_LDFLAGS`
reach the mruby build. Do not combine the sanitizers with valgrind. nginx
sends its stderr to `error.log` once the configuration is loaded, so reports
from code that runs while nginx parses the configuration (directive handlers,
script compilation, `mruby_init_code`) appear on the terminal instead; read
both. `test/ubsan.supp` lists the reports that come from nginx itself, each
with the reason. `test/lsan.supp` does the same for LeakSanitizer: nginx
never frees `cycle->connections` and the two event arrays it allocates in
`ngx_event_process_init`, and whether LeakSanitizer reports them at exit
depends on whether anything outside them still points at them, so without
the suppression a run can fail on nginx's own allocations. With the gcc 11
runtime that CI uses, a suppressed block hides nothing else; the LLVM
runtime and gcc 12 and later also treat a suppressed block as a root, so
there a block reachable only from those arrays is not reported either.
