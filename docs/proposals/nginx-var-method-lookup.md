# Proposal: the method lookup of `Nginx::Var` accessors on mruby 4

Status: decided. The owner answered the question of section 4 on
2026-10-15, in a session's question: the change of (a) to introspection is
accepted as a behavior change of 3.0.0. On 2026-10-19 the owner confirmed
the content in a session's question, with the option
"その内容で合っている (推奨)" ("that content is right"): (a) with the rule
(a2), accessors defined on `Nginx::Var` at the first miss; (d), ngx_mruby's
own methods read their variables in C; and the change that accessors appear
in introspection. The implementation is #610. The proposal was written on
2026-10-14 from `next` at e0dfdc658 (mruby 3.3.0), #561 at a33f939a9
(mruby 4.0.0; `mruby/` and the build inputs are those of #561's head,
872f3be2b on 2026-10-14, whose two later commits change only files under
`docs/`), the mruby tag `4.1.0-rc2` (commit c17ffcc24; its files read with
the GitHub API on 2026-10-14), nginx 1.31.6 (the version in
`nginx_version`), and the callgrind comparison of 2026-10-14 in the body of
#561. Section 4 says what the owner decided, with the recommendation.

## 1. The problem

### 1.1 What the comparison of #561 counts

The perf lane (`test/perf/compare.sh`; "Performance comparison with
callgrind" in `docs/test/README.md`) counts the user-space instructions
(callgrind's `Ir`) that one nginx process executes per request, over
`PERF_N=20000` requests after 2,000 warmup requests. #561 compares its head
(mruby 4.0.0) with `next` at bc2488a (mruby 3.3.0, after #572). Two of its
scenarios reach nginx variables through `Nginx::Var#method_missing`:

| Scenario | What a request runs | Ir per request without GC, 3.3.0 → 4.0.0 | Difference | Self Ir per request of `mrb_vm_find_method`, 3.3.0 → 4.0.0 | Accesses through `method_missing` per request | Lookup difference per access |
|---|---|---|---|---|---|---|
| `var` | content handler in `test/soak/nginx.conf`: reads `request_method`, `arg_q` and `soak_out` with `v.NAME`, and calls `v.set` once | 19,294 → 21,912 | +2,618 (+13.57%) | 721 → 2,650 (+1,929) | 3 | +643 |
| `auth` | server rewrite handler `test/soak/handlers/agent_auth.rb`: two Hash lookups and three `v.NAME = value` | 41,737 → 45,258 | +3,520 (+8.43%) | 793 → 2,857 (+2,064) | 3 | +688 |

The differences are those that `perf.rb` prints, computed before rounding.
The last column divides the lookup difference evenly by the accesses
(1,929 / 3 and 2,064 / 3): the profile gives one number per request and does
not separate the three accesses, so it is an average. The lookup difference
is 74% of the difference of `var` (1,929 of 2,618) and 59% of that of `auth`
(2,064 of 3,520).

The rest of each difference is in parts of mruby that no candidate below
changes: 4.0.0's `iv_get` (`mruby/src/variable.c`) finds a name by binary
search where 3.3.0 probed a hash table, which makes instance variables,
constants and globals slower, and 4.0.0 checks the argument count of a C
method before it calls it (`check_argument_count` in `mruby/src/vm.c`); the
allocator does less work (the table of #561 lists each item per scenario).

WARN starts at +3.0% and FAIL at +5.0%, both on Ir per request without GC.
Without the lookup difference, `var` would be at +689 Ir per request
(2,618 - 1,929; +3.57%) and `auth` at +1,456 (3,520 - 2,064; +3.49%), both
still WARN. A change that only brings the lookup back to the cost it has on
3.3.0 therefore does not bring either scenario under WARN; section 2 says
which candidates remove more than that.

What the numbers mean: they count the work of the user-space code of nginx,
ngx_mruby, mruby and the C library, not the kernel's work for the
connection, so the CPU time of a whole request changes by less than these
percentages. The `auth` difference is 0.31 of a `hello` request of the head
(11,428 Ir, from #561). The owner accepted the differences of #561 on
2026-10-14 (its comment "Performance: the owner accepted the remaining FAIL
rows"), and that comment names this proposal as the follow-up.

The profile counts a lookup as the self Ir of `mrb_vm_find_method`. It does
not separate lookups that find nothing from lookups that find a method that
is not in the method cache. `file`, whose request reaches no
`method_missing`, has +153 Ir per request in the same function, so other
lookups add some work as well; the misses are the part that grows with each
`v.NAME`.

### 1.2 The code path of `v.NAME`

`Nginx::Var` (`ngx_mrb_var_class_init` in `src/http/ngx_http_mruby_var.c`)
is a subclass of `Object` with three methods: `method_missing`, `exist?`
and `set`. A read such as `v.request_method` or an assignment such as
`v.agent_key_id = x` runs these steps:

1. The send instruction calls `mrb_vm_find_method` (`mruby/src/class.c`)
   for the name on `Nginx::Var`. The function looks in the method cache
   (`mrb->cache`) first, then walks from `Nginx::Var` through its ancestors
   and calls `mt_get` on the method table of each. It writes the cache only
   in the branch where `mt_get` found a method, so a name that no class
   defines is never cached, and every call searches all ancestors again.
   This is the same in 3.3.0, 4.0.0 and 4.1.0-rc2.
2. The ancestors are `Nginx::Var`, `Object`, `Kernel` (included in
   `Object`) and `BasicObject`. No gem of the default build includes a
   module into `Object` or `Kernel` (`mrb_include_module` and `include` in
   the gems of `mruby/mrbgems/`, the third-party gems that the build fetches,
   `mrbgems/` and `src/`), and in the `mruby` binary of the 4.0.0 build a
   subclass of `Object` has exactly these ancestors.
   - 3.3.0: `mt_get` probes an open-addressing hash table
     (`kh_int_hash_func`, then the next slots until it meets the name or an
     empty slot). The cost of a miss depends on how full the table is, not
     on how many methods it holds: `mt_put` grows a table only when a probe
     wraps around without an empty or deleted slot, so a table can be full,
     and a miss in a full table visits every slot. The numbers of section
     1.1 are measured and do not depend on this.
   - 4.0.0: a method table is a chain of layers (`mrb_mt_tbl`, linked by
     `next`; the entries that are added at run time sit above the read-only
     table of a core class), and `mt_get` compares the name with each entry
     of each layer. A name that no class defines is compared with every
     entry of every layer of the four classes. The 4.0.0 build of
     a33f939a9 has at least 111 such entries: 3 in `Nginx::Var`, 1 in `Object`,
     93 in `Kernel` (53 public, 40 private) plus `Kernel#server_name`, which
     ngx_mruby defines at initialization (`src/http/ngx_http_mruby_core.c`),
     and 13 in `BasicObject`. The counts of `Object`, `Kernel` and
     `BasicObject` were taken on 2026-10-14 with the `mruby` binary of that
     build (`public_instance_methods(false)`, `private_instance_methods(false)`
     and `protected_instance_methods(false)`). A layer can repeat a name of a
     lower layer, so a scan can compare more entries than there are methods.
   - 4.1.0-rc2: the same `mt_get`.
3. `prepare_missing` (`mruby/src/vm.c`) packs the arguments into a new
   `Array`, looks up `method_missing` twice (`mrb_func_basic_p`, then
   `mrb_vm_find_method`; the cache answers both) and calls it. 3.3.0 and
   4.0.0 have the same code; 4.1.0-rc2 packs with
   `mrb_args_pack_positional` and `mrb_ary_unshift`.
4. `ngx_mrb_var_method_missing` reads its arguments (`mrb_get_args` with
   `"n*"`), makes a `String` of the name (`mrb_sym_str`), copies the name
   into the request pool and calls `ngx_mrb_var_get` (`ngx_hash_strlow`,
   `ngx_http_get_variable`, a `String` of the value), or, for a name that
   ends with `=`, `ngx_mrb_var_set` (`ngx_mrb_var_set_vector`, which looks
   the name up in `variables_hash`).

Steps 3 and 4 do the same work on both versions; step 2 is the part that
grew. On both versions, each access allocates three objects that the
garbage collector frees later: the `Array` of step 3, and in step 4 the
`String` of the name and the `String` that the access returns (`mrb_str_new`
of the value read in `ngx_mrb_var_get`, or of the value assigned in
`ngx_mrb_var_set_vector`).

The method cache has 256 entries: `build_config.rb` selects no mruby
profile, so `MRB_METHOD_CACHE_SIZE` keeps the default of
`mruby/include/mruby.h` (`1<<8`, the same in 4.1.0-rc2). In 4.0.0 a class
and a name map to one entry; in 4.1.0-rc2 they map to a set of two entries
(128 sets).

The cost of a miss grows with the four tables: a `def` at the top level of
a handler script adds a private method to `Object`, and a gem that adds
methods to `Kernel` makes its table longer.

### 1.3 Who reaches this path

- Scripts, with `v.NAME` and `v.NAME = value` on an instance from
  `Nginx::Var.new`, `Nginx.var` or `Nginx::Request#var`: the accessor that
  "Nginx::Var Class" in `docs/class_and_method/README.md` documents.
- ngx_mruby's own methods that read a variable with `mrb_funcall_id` on
  the `Var` object of the request, twelve methods in eleven C functions:
  `Nginx::Connection#remote_ip`, `#remote_port`, `#local_ip` and
  `#local_port` (`src/http/ngx_http_mruby_connection.c`),
  `Nginx::Server#document_root`, `#path` and `#realpath_root`
  (`src/http/ngx_http_mruby_server.c`), and `Nginx::Request#hostname`,
  `#authority`, `#filename`, `#user` and `#get_body`
  (`src/http/ngx_http_mruby_request.c`). `mrb_funcall_with_block` takes
  the same steps 1 to 3.
- Not `Nginx::Var#set(name, value)` and `#exist?(name)`, which are defined
  methods.

A variable whose name is a method of the four classes never reaches
`method_missing`. `v.server_name` calls `Kernel#server_name`, which returns
the string `"NGINX"` (nginx's `NGINX_VAR`), not `$server_name`. The name of
a private method, such as `print`, raises `NoMethodError` (`vis_error` in
`mruby/src/vm.c`).

### 1.4 Branches

`master` keeps mruby 3.3.0, whose `mt_get` probes a hash table, so this
proposal changes nothing on `master`. The work is for `next`.

## 2. Candidates

In this section, "per access" means one `v.NAME` or `v.NAME = value`, and
"the worker" means the `mrb_state` of a worker process, which every request
of that worker shares ("Design principles" in `AGENTS.md`).

### (a) Define an accessor on `Nginx::Var` at the first miss

After `ngx_mrb_var_method_missing` has served an access, it defines a
method of that name on `Nginx::Var` with `mrb_define_method_id`, when the
rule under "Which names get an accessor" below allows it: a getter for
`NAME`, a setter for `NAME=`. The `RClass` of `Nginx::Var` and the count of
prefix accessors are kept with the `mrb_state` they belong to, in the HTTP
module's main configuration (`ngx_http_mruby_main_conf_t`), not in C static
variables: nginx creates a new `mrb_state` at each load of the
configuration while the old one can still exist (the comment of
`ngx_http_mruby_syms_t` in `src/http/ngx_http_mruby_core.h`), so a C static
would point into whichever state was initialized last ("Where the state
is" in "Design principles" of `AGENTS.md`). The two C functions take the
name of the variable from the name they were called with (`mrb_get_mid`).
The next access in the worker finds the method in the method cache, or,
when another method has taken the cache entry, in the table of
`Nginx::Var`, which is the first table of the walk.

- For a script: the same values are read and written. The defined methods
  call the same `ngx_mrb_var_get` and `ngx_mrb_var_set` code, with the same
  `nil` for a name that is not a variable and the same `error.log` lines.
  They are defined with `MRB_ARGS_ANY()`, so a call with extra arguments
  behaves as it does through `method_missing` (the getter ignores them).
- Per access, from the second access of a name in the worker: one lookup
  that the cache answers, the argument count check of 4.0.0, and the rest
  of step 4 of section 1.2: the copy and lowercasing of the name in the
  request pool, `ngx_http_get_variable` (for a setter, the lookup in
  `variables_hash`) and the `String` of the value. Step 2 (the scan), step
  3 (the `method_missing` dispatch and its `Array`) and, of step 4,
  `mrb_get_args` and the `String` of the name do not run, so two of the
  three objects of an access are not allocated. The lane measures this
  state, because the warmup requests make the first accesses.
- Per first access of a name in the worker: the steps of today, the check
  of the rule below (`ngx_hash_find` in `variables_hash`, then a comparison
  with each entry of `prefix_variables`), and, when the rule allows it,
  `mt_put` into the table of `Nginx::Var` and `mc_clear_by_id`, which
  visits the 256 cache entries once. A name that the rule does not allow
  pays the check on each access.
- Memory: one entry of 16 bytes (`mrb_mt_entry` on a 64-bit build) per
  accessor in the table of `Nginx::Var`, kept for the life of the worker;
  the table starts at 8 entries and doubles when it is full. The garbage
  collector gets no object: a method in C is stored as a function pointer.
- Which names get an accessor. nginx keeps two tables of names after the
  configuration, and `ngx_http_get_variable` (`src/http/ngx_http_variables.c`
  of nginx 1.31.6) looks a name up in both: first `cmcf->variables_hash`,
  the declared variables (those of nginx and its modules, and those that
  `set` declares), then `cmcf->prefix_variables`, the families whose names
  start with a fixed prefix (`arg_`, `http_`, `cookie_`, `sent_http_`,
  `sent_trailer_` and `proxy_protocol_tlv_` in `ngx_http_variables.c`,
  `upstream_http_`, `upstream_trailer_` and `upstream_cookie_` in
  `ngx_http_upstream.c`). A name in neither gets a value marked
  `not_found`, and the accessor returns `nil` for it. So `method_missing`
  can tell a declared name, a prefix name and an unknown name apart with
  the same two lookups (`ngx_mrb_var_set_vector` already calls
  `ngx_hash_find` on `variables_hash`). The declared names are a set that
  the configuration fixes. The prefix names are not: every suffix makes a
  name, so `v.send("arg_#{x}")` brings as many names as the requests
  choose. Two rules bound the table:
  - (a1) The first 32 names that the worker serves, whatever they are (35
    entries with the 3 methods of today, which fit in a table of 64
    entries, 1,024 bytes). A getter and a setter of the same variable are
    two of the 32, and so are two spellings of one name, such as
    `request_method` and `Request_Method`. The order of the requests
    decides which names get an accessor for the life of the worker: typing
    errors and names that request data selects through `send` count as
    well, so names that a script reads on every request can be left on the
    slow path, and two workers can end with different sets.
  - (a2) Every declared name that a script uses, at most 16 prefix names
    (a number chosen here), and no unknown name. Setters exist only for
    declared names, because `ngx_mrb_var_set_vector` assigns only names of
    `variables_hash`; an assignment to a prefix name logs that it is not
    found today and keeps doing so.
  - Letter case under (a2). The getter and the setter lowercase the name
    before they look it up (`ngx_hash_strlow`), so today `v.Request_Method`
    and `v.REQUEST_METHOD` read `$request_method`. Each spelling is a
    different method name, so a check that lowercased the name first would
    let every spelling of a declared name pass and get an accessor of its
    own, and a script that passes names from request data to `send` would
    add accessors without a bound. (a2) therefore defines an accessor only
    for a called name without an uppercase letter (`A` to `Z`, the letters
    that `ngx_hash_strlow` changes); another spelling keeps working through
    `method_missing` with the same value, and pays the check on each
    access. Counting such spellings against the 16 would also bound the
    table, but request data could then take the slots that the prefix names
    read on every request need. Keeping other spellings on the slow path
    costs little: the documentation, tests and gems of this repository
    spell every variable in lowercase, as the nginx documentation does.
  - With that rule, the configuration fixes the declared part of the table
    (at most a getter and a setter per declared variable that scripts use,
    in its lowercase spelling), and the order of the requests decides only
    which prefix names get the 16. The table has at most 3 + 2 × (the
    declared variables that scripts use) + 16 entries.
  - Accessors only for declared names, without prefix names, would leave
    `arg_q` of `var` on the slow path: one of its three accesses per
    request, about a third of its lookup difference (about +643 Ir, an even
    split of +1,929 over the three accesses; the profile does not separate
    them).

  This proposal recommends (a2). The names that scripts read on every
  request are mostly declared names (the variables of nginx such as
  `request_method` and `remote_addr`, and the variables of `set`, as in
  `auth`), and under (a2) they get an accessor whatever the order of the
  requests and whatever typing errors a script makes; only the open family
  of prefix names keeps a bound. The rest of this proposal uses (a2).
- Past the bound, and for unknown names, an access is not as today on
  4.0.0. Its miss scans the entries of `Nginx::Var` (3 today, 3 plus the
  accessors with (a)) before the 111 of section 1.2, and so does every
  lookup of a method of `Object`, `Kernel` or `BasicObject` on a `Var` (for
  example `v.inspect`) that the cache does not answer. Under (a1) this
  starts after 32 names, with 35 entries of `Nginx::Var` instead of 3.
- Design principles: what is defined at the first use is shared by every
  later request of the worker. The definitions hold no request data (a
  symbol and a function pointer), so no value of one request reaches
  another; under (a2) only the set of prefix accessors depends on which
  requests the worker served first. No allocation per request is added,
  and two of the three objects per access are removed. Nothing blocks.
- Compatibility, as behavior changes of 3.0.0 on `next`:
  - After the first access of a name that gets an accessor in a worker,
    `v.respond_to?(:NAME)` returns `true`, where it returns `false` today
    (`Nginx::Var` defines no `respond_to_missing?`), and
    `Nginx::Var.instance_methods(false)`,
    `v.methods`, `Nginx::Var.method_defined?(:NAME)` and `v.method(:NAME)`
    show the method. The answer depends on what the worker has served, so
    two workers can answer differently.
  - Once the accessor exists, a method that a script defines later with the
    same name on `Object` or `Kernel` (for example with a `def` at the top
    level) no longer hides the variable from `v.NAME`, because `Nginx::Var`
    comes first in the walk. Today such a method is called instead, or, when
    it is private (as a `def` at the top level is in 4.0.0), `v.NAME` raises
    `NoMethodError`.
  - A method that a script defines on `Nginx::Var` itself replaces the
    accessor, as such a method takes precedence over `method_missing` today.
  - An alias made in Ruby of a defined accessor reads the variable of the
    alias's name, because the C function takes the name from the call.
  - A script that freezes `Nginx::Var` would make `mrb_define_method_id`
    raise `FrozenError`, so (a) does not define a method on a frozen class
    (`mrb_frozen_p`), and such a script keeps today's behavior.
- Variant: store the lowercased name and its hash key once per name in the
  environment of a C proc (`mrb_proc_new_cfunc_with_env`). It removes the
  per-access copy and lowercasing of the name and the alias property above,
  and costs one proc and one environment object per name for the life of
  the worker. The implementing pull request measures whether it is worth
  it.

### (b) Methods that take the name as an argument

`Nginx::Var` has no `[]` today: `v["request_method"]` reaches
`method_missing` as a variable named `[]` and returns `nil`. (b) adds
`Nginx::Var#[](name)` and `#[]=(name, value)` in C, with `name` a `String`
or a `Symbol`. `#[]=` shares the C code of `Nginx::Var#set`, which already
exists and already assigns without `method_missing`. The documented `v.NAME`
stays as a thin path from `method_missing` into the same getter and setter.

- For a script: nothing changes until the script is rewritten. With
  `v[:NAME]`, an access costs one lookup that the cache answers and no
  scan. A `Symbol` allocates nothing for the name; a `String` literal
  allocates a new `String` each time it is evaluated (`OP_STRING` in
  `mruby/src/vm.c`). `v["server_name"]` reaches `$server_name`, which
  `v.server_name` cannot reach (section 1.3).
- Per access: for `v[:NAME]`, about what (a) costs; for `v.NAME`, the cost of
  today.
- Memory: two method entries, defined at initialization.
- Compatibility: `v[name]` returns the variable instead of `nil`, and
  `v[name] = value` assigns the named variable, where today it tries a
  variable named `[]`, logs that it is not found and returns `nil`. This
  changes what a Ruby method returns and is recorded as a behavior change,
  although a script that relies on the `nil` is unlikely.
- The lane: `var` and `auth` use `v.NAME`, so their numbers do not change.
  Rewriting them to `v[:NAME]` would measure another API and hide the cost
  of the documented accessor, so (b) alone does not remove the difference
  of section 1.1.

### (c) Change nothing and accept the cost

- Per access: +643 Ir (`var`) and +688 Ir (`auth`) in the lookup against
  3.3.0, on average (the even split of section 1.1 of what #561 measured).
  It grows with the methods of `Object` and `Kernel`.
- The agent proxy baseline `auth` - `proxy_plain_2k` of
  `docs/proposals/v3-plan.md` stays at 25,276 Ir per request with 4.0.0,
  against 21,934 with 3.3.0 (+15.2%, from #561).
- No compatibility change. This is the state that the owner accepted for
  #561.

### (d) ngx_mruby's own methods read the variable in C

The twelve methods of section 1.3 call `mrb_funcall_id` on the `Var` object
with a fixed name. (d) makes them call the C getter directly, with the name
and its hash key prepared once at initialization. This applies the rule of
"Design principles" in `AGENTS.md` that nothing fixed (a class reference, a
symbol name, a buffer) is looked up or allocated per request when it can be
prepared once at initialization.

- For a script: the same values. Per call: no `Var` object, no Ruby call,
  no scan and no `method_missing` dispatch. `ngx_mrb_get_request_var`
  allocates a `Var` for each `Nginx::Request`, `Nginx::Connection` or
  `Nginx::Server` object on which one of these methods is called (each
  passes its own `self`), keeps it in an instance variable of that object,
  and on the first call per object also looks up `Nginx` and `Nginx::Var`
  (`mrb_class_get_id`, `mrb_const_get`); (d) removes these as well.
- Compatibility: today, a script that defines `Nginx::Var#remote_addr` (or
  a `method_missing` of its own) changes what `Nginx::Connection#remote_ip`
  returns; after (d) it does not. This is recorded as a behavior change.
- The lane: no scenario calls these methods, so the implementing pull
  request states the change per call as read from the diff (calls,
  allocations, copies).
- (d) is independent of (a) and (b). With (a) alone, these calls find the
  accessor from their second call in the worker, but they still allocate the
  `Var` object and make the Ruby call.

### (e) Change mruby

Two changes in mruby itself would remove the scan for every user of
`method_missing`: a cache entry that records that a class has no method of
a name, or an index for long method tables. mruby already clears the cache
entries of a name when a method of that name is defined (`mc_clear_by_id`)
and clears the whole cache when a module is included (`mrb_method_cache_clear`
in `include_module_at`); an entry for a missing name would rely on both. It
is a change upstream: `mruby/` is not edited by hand ("Do not" in
`AGENTS.md`), the change would reach ngx_mruby only with a mruby release
that is vendored, and 4.1.0 is at its second release candidate. This
proposal does not pursue it.

### (f) Define accessors for every declared variable when the worker starts

nginx does not keep the list of declared variable names after the
configuration: `ngx_http_variables_init_vars` builds `variables_hash` from
`cmcf->variables_keys`, which lives in the temporary pool, and sets
`variables_keys` to `NULL`. The hash table has no iteration API, and the
prefix variables (`arg_`, `http_`, `cookie_` and the others) have no fixed
names, so a name such as `arg_q` would still go through `method_missing`,
with a longer table of `Nginx::Var` in front of the scan. This proposal does
not pursue it.

## 3. How it is measured

The pull request that implements the change is measured with the perf lane
of `next` (`test/perf/compare.sh`), the default scenarios and
`PERF_N=20000`, in three comparisons. `B33` is e0dfdc658, the first parent
of 0b76bfa6d (the merge commit of #561), the last commit of `next` with
mruby 3.3.0.

| Comparison | Base | Head | What it shows | Acceptance |
|---|---|---|---|---|
| The `perf` job of the pull request | `next` with mruby 4.0.0 | the pull request | the effect of the change on 4.0.0, and that no other scenario moves | the rules of "Design principles" in `AGENTS.md`: no scenario at WARN, FAIL or ERROR |
| Against mruby 3.3.0 | `B33` | the pull request | whether the differences of section 1.1 are gone | `var` and `auth` below WARN: less than +3.0% Ir per request without GC |
| On 4.1.0-rc2 | `B33` | the pull request with `mruby/` replaced by the tree of the tag `4.1.0-rc2` | the same on the release candidate of the version that v3 targets | as the row above |

The two rows against `B33` are run from a checkout of the pull request's
head (Linux with valgrind; on macOS, run each `compare.sh` line in the
container as "The `master` commands" in `AGENTS.md` shows):

```sh
git fetch origin next
B33=e0dfdc658                 # the first parent of 0b76bfa6d, the merge of #561
D=$HOME/ngx_mruby-perf-var    # any directory outside the checkout
rm -rf "$D" && mkdir -p "$D/base33" "$D/head40" "$D/head41/mruby"
git archive "$B33" | tar -x -C "$D/base33"
git archive HEAD | tar -x -C "$D/head40"
git archive HEAD -- . ':!mruby' | tar -x -C "$D/head41"
git fetch --no-tags https://github.com/mruby/mruby.git refs/tags/4.1.0-rc2   # FETCH_HEAD only
git archive FETCH_HEAD | tar -x -C "$D/head41/mruby"
cd "$D/head40"
sh test/perf/compare.sh "$D/base33"; cp build_perf/report.txt "$D/report-4.0.0.txt"
sh test/perf/compare.sh "$D/base33" "$D/head41"; cp build_perf/report.txt "$D/report-4.1.0-rc2.txt"
```

The pull request quotes, for each comparison, the header lines of
`report.txt` and its table, and the commits compared. For `var` and `auth`
it also gives the self Ir per request of `mrb_vm_find_method` in the base
and the head (`callgrind_annotate --inclusive=no` of
`build_perf/{base,head}/callgrind/callgrind.out.<scenario>`, divided by
`PERF_N`). The scan is gone when the head's number is at or below the
base's; the base's numbers in the run of #561 were 721 (`var`) and 793
(`auth`).

When a row of `var` or `auth` stays at WARN or above, the pull request
attributes the remaining difference by the items that #561 uses (method
lookup, constant lookup, instance variables, argument count check, global
variables, allocator), and the owner decides on the pull request, as
"Design principles" in `AGENTS.md` says. When the tree of 4.1.0-rc2 does not
build with the head's `build_config.rb` (a core gem that the list names and
4.1.0-rc2 does not have; `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` skips it, as
`build_config.rb` explains), the pull request quotes the error, and that row
is measured again in the pull request that updates mruby to 4.1.0.

The same pull request also has:

- tests with a `server {}` of their own in `test/conf/conf.d/` and a case
  file in `test/t/cases/` ("Writing tests" in `AGENTS.md`), which assert on
  the responses: the value of `v.NAME` on several consecutive requests (the
  test nginx runs one worker, so the first request defines the accessor and
  the later ones use it); an assignment with `v.NAME = value` that nginx
  reads back (`add_header` with `$NAME`); `respond_to?(:NAME)` before and
  after the first access; a prefix name past the bound of 16, a name that
  is neither declared nor a prefix name, and a declared name spelled with an
  uppercase letter (`v.Request_Method`), which keep working through
  `method_missing` with the same values and get no accessor
  (`respond_to?` stays `false`); and, for (d), the value of each of the
  twelve methods;
- the soak test (`sh test/soak/run.sh`) with its scenarios passing, since
  (a) adds a table that grows once per worker;
- the "Nginx::Var Class" section of `docs/class_and_method/README.md`
  updated to say that an accessor becomes a method of `Nginx::Var` at its
  first use in a worker, for the declared variables and for up to 16
  prefix names;
- an entry under "Behavior changes: read before upgrading" in
  `docs/releases/v3.0.0.md` for each compatibility item of section 2 that
  the pull request brings.

## 4. Recommendation and what the owner decides

Recommended: (a) with the rule (a2) of section 2, and (d), together in one
pull request to `next`, which has mruby 4.0.0 since 0b76bfa6d (#561). (c)
is the state until that pull request merges. (b), (e) and (f) are not part
of this work.

The reasons:

- (a) is the only candidate inside this repository that removes the cost
  for scripts as they are written today, and the lane measures that path.
  It removes step 2 (the scan), step 3 (the `method_missing` dispatch,
  which 3.3.0 also runs) and, of step 4, `mrb_get_args` and the `String` of
  the name. It is therefore expected to bring `var` and `auth` below their
  3.3.0 numbers, where removing only the extra cost of the scan would leave
  both at WARN (section 1.1). The measurement of section 3 decides.
- (a), with the rule (a2), costs one table entry of 16 bytes per accessor
  for the life of the worker: at most two per declared variable that
  scripts use, and at most 16 for prefix names. Its behavior change is
  limited to what introspection shows (`respond_to?`, `methods`,
  `instance_methods`) and to the order of lookup against methods defined
  later on `Object` or `Kernel`; values, errors and log lines do not
  change.
- (d) applies the rule of `AGENTS.md` on fixed lookups to ngx_mruby's own
  calls, and changes nothing for a script that does not redefine methods of
  `Nginx::Var`.
- (b) helps only scripts that are rewritten and does not change the measured
  difference. Its other use, reaching `$server_name` and the other names that
  are also methods of the ancestors, is a separate question of API, which can
  be a proposal of its own.

The owner decides one question:

- **Accept the change of (a) to introspection as a behavior change of
  3.0.0?** After its first use in a worker, an accessor shows in
  `respond_to?`, `methods` and `instance_methods` of `Nginx::Var`.
  Recommended: accept. It does not change a value that a script reads or
  writes, it applies to `next` only, and a later release can remove the
  definitions without changing values. If not accepted: (d) alone, (c) for
  the documented accessor, and (b) as a separate proposal for scripts that
  want the faster path.

The rule (a2) and its bound of 16 prefix names are chosen here; the review
of the implementing pull request can change them.

## 5. Status and steps

Status: decided, as the Status line at the top says (the owner's answer
of 2026-10-15 and the confirmation of 2026-10-19). #610 implements (a)
with the rule (a2) and (d), with the steps below.

1. After the owner's answer: a pull request to `next` with (a) and (d), or
   with the fallback of section 4, its tests, the docs and the release notes
   entries (section 3).
2. In that pull request: the three comparisons of section 3.
3. When `var` or `auth` stays at WARN or above against 3.3.0: the owner
   decides on that pull request, with the attribution of section 3.
4. The pull request that updates mruby to 4.1.0 measures `var` and `auth`
   again, as every change of `mruby/` is measured.

Relation with the plan: the Pillar B row of `docs/proposals/v3-plan.md`
on `Nginx::Var` asks for one setter shared by `set` and assignment through
`method_missing`. The setter that (a) defines can be that shared setter;
the pull request says whether it is.

## Sources

Read on 2026-10-14:

- `mruby/src/class.c`: `mt_get`, `mt_put`, `mrb_vm_find_method`,
  `mrb_define_method_raw`, `mrb_define_method_id`, `mc_clear_by_id`,
  `include_module_at`; in 3.3.0 on `next` at e0dfdc658 (with its `mt_put`),
  in 4.0.0 at a33f939a9 (`mruby/` of #561's head 872f3be2b), in 4.1.0-rc2
  at c17ffcc24 (GitHub API).
- `mruby/src/vm.c`: the send instruction, `prepare_missing`,
  `check_argument_count` (4.0.0 and 4.1.0-rc2), `check_method_noarg`
  (3.3.0), `vis_error`, `OP_STRING`; `mruby/src/variable.c`: `iv_get`;
  `mruby/src/kernel.c`: `mrb_func_basic_p`; `mruby/src/symbol.c`:
  `mrb_sym_str`; `mruby/include/mruby.h` and `mruby/include/mrbconf.h`:
  `MRB_METHOD_CACHE_SIZE`; `mruby/include/mruby/class.h`: `mrb_mt_entry`,
  `mrb_mt_tbl`.
- `src/http/ngx_http_mruby_var.c`, `src/http/ngx_http_mruby_request.c`,
  `src/http/ngx_http_mruby_connection.c`, `src/http/ngx_http_mruby_server.c`,
  `src/http/ngx_http_mruby_core.c`, `src/http/ngx_http_mruby_core.h`,
  `src/http/ngx_http_mruby_module.h`,
  `mrbgems/ngx_mruby_mrblib/mrblib/mrb_nginx.rb` and
  `docs/class_and_method/README.md` on `next` at e0dfdc658.
- nginx 1.31.6, `src/http/ngx_http_variables.c`: `ngx_http_get_variable`,
  `ngx_http_variables_init_vars`, `ngx_http_core_variables`;
  `src/http/ngx_http_upstream.c`: the prefix variables of the upstream
  module; `src/core/nginx.h`: `NGINX_VAR`.
- `test/perf/perf.rb`, `test/perf/compare.sh`, `test/soak/nginx.conf`,
  `test/soak/nginx.agent.conf`, `test/soak/handlers/agent_auth.rb` on
  `next` at e0dfdc658.
- #561: its body (the revision of 2026-10-14, "Leak / performance impact")
  and its comment "Performance: the owner accepted the remaining FAIL rows"
  (2026-10-14).
- The method counts of section 1.2: the `mruby` binary of the 4.0.0 build
  in a checkout of a33f939a9, run in an aarch64 Linux container.
