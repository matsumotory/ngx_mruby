<!--
Fill in every section; write "n/a" where one does not apply.
Do not describe security vulnerabilities here. Report them privately (see SECURITY.md).
-->

## Summary

<!-- What does this change, and why? Link related issues. -->

## Target branch

- [ ] `master`: 2.x fix or maintenance (until v3 is promoted)
- [ ] `next`: v3 development
- Backport to 2.x needed? <!-- yes / no, and why -->

## How was this tested

<!--
Exact commands and their results, e.g. `sh test.sh`, `BUILD_DYNAMIC_MODULE=1 sh test.sh`,
with the nginx version used.
Bug fixes: show that the new test fails on the base branch and passes with this PR.
-->

## Memory / sanitizer checks (C changes)

<!--
Which of valgrind (`NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh`), ASan, UBSan
did you run, and what was the result (ERROR SUMMARY, leak summary, sanitizer
reports in error.log)?
-->

## Leak / performance impact

<!-- Required when async, filter or GC-related code is touched: what was measured, and how. -->

## Compatibility / behavior changes

<!-- Changes to directives, the Ruby API, handler return values, build options or supported versions. -->

## Checklist

- [ ] Patches are in `src/` (C) or `mrbgems/` (Ruby).
- [ ] Tests are in `test/`. Please see the [test docs](https://github.com/matsumotory/ngx_mruby/tree/master/docs/test).
- [ ] Docs are updated in `docs/` if you change features such as the [build system](https://github.com/matsumotory/ngx_mruby/tree/master/docs/install), [Ruby methods and classes](https://github.com/matsumotory/ngx_mruby/tree/master/docs/class_and_method) or [nginx directives](https://github.com/matsumotory/ngx_mruby/tree/master/docs/directives).

## AI assistance

<!-- Was an AI tool used? Which one, and for what (code, tests, docs, PR text)? Did a human review the result? -->
