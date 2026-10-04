# Migrating to the bundled mruby 4.0.0

ngx_mruby 2.x bundles mruby 3.3.0. The development line of ngx_mruby 3
bundles mruby 4.0.0, the current stable release of mruby. The v3 plan
(`docs/proposals/v3-plan.md`, section 7, decision 1) sets mruby 4.1.0 as
the target of v3, not 4.0.0; 4.1.0 has only release candidates so far. This
page lists changes of mruby 4.0.0 that a script running in ngx_mruby can
see, and what to do about them. The list is not complete: it has the
changes that were found and measured for ngx_mruby. mruby's own lists of
user-visible changes are `doc/mruby3.4.md` and `doc/mruby4.0.md` in
`mruby/`. mruby 4.1.0 brings further changes that this page does not cover
yet. Build changes are in [Core gems](../install/README.md#core-gems) of
the install guide.

## How the changes were found

Each change below was measured on 2026-10-04 by running the same Ruby
script with two `mruby` binaries, one built from the mruby tree of
ngx_mruby 2.x (mruby 3.3.0) and one from mruby 4.0.0, both with mruby's
`default` gembox, in Docker (Ubuntu 22.04, gcc 11). The changes marked
"seen in nginx" also changed a response or a log line of ngx_mruby itself
(its test suite, or `error.log`).

## Changes that scripts can see

| Area | ngx_mruby 2.x (mruby 3.3.0) | mruby 4.0.0 | What to do |
|---|---|---|---|
| `Hash#inspect` and `Hash#to_s`, and everything that prints a Hash with them: string interpolation (`"#{h}"`), `sprintf("%s", h)`, `Array#inspect` (seen in nginx) | `{"a"=>1}`, `{:a=>1}` | `{"a" => 1}`, `{a: 1}` | Do not use `inspect` or `to_s` of a Hash as a data format, in a response body or in a header. Build the string yourself, or use `JSON.generate`. |
| `Exception#inspect`, and so the exception that ngx_mruby writes to `error.log` (`mrb_run failed: ... error: ...`) (seen in nginx) | `boom (RuntimeError)` | `#<RuntimeError: boom>` | Update log parsers and alerts that match the old form. `Exception#message` and `#to_s` are unchanged. |
| Message of `NoMethodError` | `undefined method 'foo'` | `undefined method 'foo' for NilClass` | Match on the exception class, not on the message. |
| `private` and `protected` | not enforced | enforced: a method defined after `private` or `protected`, `initialize`, a method defined with `def` at the top level, and the `Kernel` methods such as `raise`, `sprintf` and `puts` raise `NoMethodError` when called with an explicit receiver other than `self` | Call them without a receiver, or with `send`. `Kernel.format(...)` (a module function called on `Kernel`) still works. |
| `Module#remove_const`, `#private`, `#public`, `#protected` and `#module_function`, and the hooks `#included`, `#extended`, `#inherited` and `#method_added` | public: `Foo.remove_const(:X)` and `M.included(Foo)` work | private: called with an explicit receiver, they raise `NoMethodError: private method ... called` | Call them in the body of the class or module without a receiver, or with `send` (`Foo.send(:remove_const, :X)`). |
| Overriding `append_features`, `prepend_features` or `extend_object` in a module | `include`, `prepend` and `extend` call the override | the three methods are gone, and `include`, `prepend` and `extend` add the module without calling them, so an override is skipped without an error. The hooks `included`, `prepended` and `extended` are still called | Move the code to `included`, `prepended` or `extended`. |
| `allbits?`, `anybits?` and `nobits?` | methods of `Numeric`, so they work on a Float (`1.5.allbits?(1)` is `true`) | methods of `Integer` only; on a Float, `NoMethodError` | Convert a Float with `to_i` first. |
| `FileTest` | a class | a module; `FileTest.exist?` and its other methods are called as before | Nothing for calls of its methods. |
| Assigning a constant inside a method body (`def m; X = 1; end`) | allowed | `SyntaxError: dynamic constant assignment`, when the script is compiled | Use `Object.const_set(:X, 1)` (or `Kernel.const_set`). The Rack-style `Kernel#run` of ngx_mruby does this for `Server`. |
| The bit operations of Float: `~`, `&`, `\|`, `^`, `>>` and `<<` | `~`, `&`, `\|` and `^` work on the integer part (`1.5 & 1` is `1`, `~1.5` is `-2`). `<<` multiplies the Float by powers of two and then truncates (`1.5 << 1` is `3`, `-1.5 << 1` is `-3`). `>>` divides a positive Float by powers of two and then truncates (`8.0 >> 1` is `4`, `1.5 >> 1` is `0`), and returns `-1` for every negative Float (`-8.0 >> 1` is `-1`) | `NoMethodError` (all six removed in mruby 3.4) | For `~`, `&`, `\|` and `^`, convert with `to_i` first. For `<<` and `>>`, `to_i` first can give another number (`1.5.to_i << 1` is `2`, `-8.0.to_i >> 1` is `-4`); where the old number matters, multiply a Float, or divide a positive Float, by the power of two and then call `to_i`, and use `-1` for a right shift of a negative Float. |
| `String#valid_encoding?` | defined by mruby-string-ext. With the default `build_config.rb`, ngx_mruby 2.x builds mruby without `MRB_UTF8_STRING`, and the method returns `true` for every string, even `"\xfe"`. A build whose `build_config.rb` defines `MRB_UTF8_STRING` gets `false` for a string that is not valid UTF-8 | `NoMethodError`: since mruby 3.4 only mruby-encoding defines it, and the default build of ngx_mruby leaves that gem out | With the default `build_config.rb` of 2.x, drop the call (it never returned `false` there), or build with mruby-encoding and check the scripts as [Core gems](../install/README.md#core-gems) says. A 2.x build that defined `MRB_UTF8_STRING` needs mruby-encoding to keep the check. |
| `Random.new(seed)`, `srand(seed)` | one sequence | another sequence for the same seed (mruby 4.0 uses PCG instead of xoshiro) | Do not depend on the numbers of a seeded generator across versions. |
| `Dir.children`, `Dir#each_child` (seen in nginx) | include `.` and `..` (aliases of `Dir.entries` and `Dir#each`) | leave `.` and `..` out, as in CRuby (since mruby 3.4) | Remove code that skipped `.` and `..` after these calls, or keep using `Dir.entries`. |
| `Set#inspect` | `#<Set: {1, 2}>` | `Set[1, 2]` | As for `Hash#inspect`. |
| `Hash#default_proc=` with an object that is not a Proc | accepted | `TypeError` | Pass a Proc or `nil`. |
| `yield` with keyword arguments to a block that takes keyword parameters | `ArgumentError: missing keyword` | works | Nothing; a bug fix. |

Not changed, checked the same way: `String#size` and `#length` count bytes
(the mruby-encoding gem is not in the default build; see
[Core gems](../install/README.md#core-gems)); the `ArgumentError` for a wrong
number of arguments; `Exception#message`; `Struct#inspect`; `Float#to_s`;
Integer division and modulo; `Kernel#sleep` and `#usleep` (from
mruby-sleep).

New in mruby 3.4 and 4.0, with no effect on existing scripts: pattern
matching (`case`/`in`), `Array#rfind`, trailing commas in
method parameters, and `&nil` in method parameters. `Time#strftime` is
in mruby 4.0 as the separate gem mruby-strftime, which the default build
does not include.

## For authors of C extensions and mrbgems

- A gem that wraps a C struct with `Data_Wrap_Struct` or
  `mrb_data_object_alloc` in an object of its own class must declare the
  class with `MRB_SET_INSTANCE_TT(klass, MRB_TT_DATA)`. Without it, mruby
  4.0 raises `TypeError: allocation failure of <class>` at the allocation;
  mruby 3.x did not check a class whose instance type was not set. The
  default build pins matsumotory/mruby-uname to a commit that does this.
- mruby 4.0 checks the number of arguments of a C method against the
  argument spec it was defined with (`MRB_ARGS_REQ(2)` and so on) before
  it calls the method. A method whose spec asks for more arguments than
  its `mrb_get_args` reads now raises `ArgumentError` where it used to
  work.
- `mruby/ext/io.h` is now `mruby/io.h`, `mrb_alloca()` is now
  `mrb_temp_alloc()`, and `mrb_open()` returns the state with
  `mrb->exc` set, instead of `NULL`, when a gem initializer fails.
- Every source that includes `mruby.h` needs the headers that the mruby
  build generates (`build/host/include`, for `mruby/presym/id.h`), because
  presym can no longer be turned off.
