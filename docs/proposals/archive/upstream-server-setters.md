# Proposal: the upstream server setters with a `zone`, and their form in v3

Status: done, except that the documentation of the setters does not point at
the balancer API yet, because the API does not exist; the row "Ruby balancer
API" of `docs/proposals/v3-plan.md` on `next` carries that. Question 1 of
section 4 was decided on 2026-10-29, questions 2 and 3 on 2026-10-30. #652
made the changes of step 1 on `master` (`8593d0d65`), which reached `next`
with #658; #648 documented the per-worker meaning of step 2; #680 made the
changes of step 3. Written on 2026-10-29 from `master` at `c6d3b3b9b` (2.7.2
and #645), `next` at `67ad9b919`, and the source of nginx 1.31.8 (the version
in `nginx_version`). It follows the review of #624, which left three points
for later: the stream setter takes no lock on the peer, the two setters raise
different exception classes for the same argument, and their argument checks
were not documented (the last point is #648 on `master`).

## 1. What the setters do in 2.7.2

`Nginx::Upstream#server=` (HTTP) and `Nginx::Stream::Connection#upstream_server=`
(stream) change the address of an `upstream {}` block whose servers that are
not `backup` have one address in all (`peers->number`, which nginx's
round-robin initialization counts; `Nginx::Upstream.new` and
`Nginx::Stream::Connection.new` raise for more).

- Both change that round-robin peer itself, which every later request or
  session of the worker uses, not only the current one: the name and the
  sockaddr are copied into one store per peer in the cycle pool, and the
  peer points at that store (`src/http/ngx_http_mruby_upstream.c:133-244`,
  `src/stream/ngx_stream_mruby_connection.c:97-198`). Each worker has its
  own peer and store.
- The HTTP setter parses the string with `ngx_parse_url` with port 80 by
  default and without `no_resolve` (`ngx_http_mruby_upstream.c:210-219`), so
  a host name is resolved with the system resolver while the worker waits
  (`ngx_inet_resolve_host`, `src/core/ngx_inet.c:975-981` of nginx). The
  stream setter sets `no_resolve` (`ngx_stream_mruby_connection.c:169-179`)
  and raises for a host name.
- For an empty string or one of 256 bytes or more, the HTTP setter raises
  `ArgumentError` and the stream setter `RuntimeError`
  (`ngx_http_mruby_upstream.c:198-200`, `ngx_stream_mruby_connection.c:159-161`).
  For a string that nginx cannot parse, both raise `RuntimeError`
  (`ngx_http_mruby_upstream.c:214-219`, `ngx_stream_mruby_connection.c:174-179`).
- The HTTP setter takes the read lock of the peers and the lock of the peer
  while it changes the peer (`ngx_http_upstream_rr_peers_rlock` and
  `ngx_http_upstream_rr_peer_lock`, `ngx_http_mruby_upstream.c:232-241`); the
  stream setter takes no lock. These locks do something only when the peers
  are in a shared memory zone (`peers->shpool`,
  `src/http/ngx_http_upstream_round_robin.h:135-165` of nginx). Without a
  zone, the peers belong to one worker, which runs in one thread, and neither
  setter needs a lock.

## 2. An upstream with a `zone`

With a `zone` directive, nginx copies the peers into the slab of the shared
memory zone, which every worker shares, and sets `peers->shpool`
(`ngx_http_upstream_zone_copy_peers`,
`src/http/modules/ngx_http_upstream_zone_module.c:232-269` of nginx; the
stream module does the same). Both setters then point a shared peer at the
memory of one worker, which the other workers cannot use. The release notes
of 2.7.2 say so under "Not changed by this release" of the entry on these
setters (`docs/releases/v2.7.2.md:558-564` on `master`), and the comments of
both setters say that only the case without a zone is handled. With one
worker (`worker_processes 1`), the setters work with a zone today, because
no other worker reads the peer.

nginx also manages the peers of a zone upstream itself: since nginx 1.27.3
(CHANGES, 26 Nov 2024) a server of an upstream block with a zone can have the
`resolve` parameter, and nginx then replaces the peers when the name resolves
to other addresses. A module that changes the name and address of such a
peer in place works against that. A lock alone, which the review of #624
asked for in the stream setter, does not make the zone case correct, because
the stored name and sockaddr are still in the memory of one worker.

## 3. Options

- **0. Documentation only.** Keep the code; the documentation (#648) says
  that a zone upstream is not supported and not checked. Configurations with
  a zone and several workers keep getting a peer that only one worker can
  use.
- **A. Refuse an upstream with a zone.** Both setters raise before they
  change anything when `peers->shpool` is set, with a message that names
  the zone. `shpool` exists only in builds with the upstream zone module
  (`NGX_HTTP_UPSTREAM_ZONE`, `NGX_STREAM_UPSTREAM_ZONE`), so the check is
  inside the same `#if`. Small, and the same on `master` and `next`. A
  configuration that uses a setter on a zone upstream gets an exception, also
  with `worker_processes 1`, where the setter works today: the release notes
  must say so.
- **B. Store the name and the sockaddr in the zone's slab.** The setters
  allocate in `peers->shpool` under the write lock of the peers and free the
  old values, as the zone module does for its own copies. The change then
  applies to every worker at once, unlike the per-worker change without a
  zone, and it still conflicts with nginx's own replacement of the peers
  under `resolve`.
- **C. Choose the peer per request in v3.** The plan has the row "Upstream
  peer hook" in the table of "Agent proxy: the v3.0 use case"
  (`docs/proposals/v3-plan.md` on `next`; Pillar C, step 7c), which wraps the
  peer functions of an upstream without changing its configured peers, and
  the row "Ruby balancer API" (`mruby_upstream_balancer`), which is built on
  that hook and lets a script choose the peer for each attempt of a request,
  as `ngx.balancer.set_current_peer` does in OpenResty's `balancer_by_lua*`.
  The plan puts the balancer API after v3.0.0, so in v3.0 the hook alone does
  not let a script choose a peer, and the two setters stay the way to change
  a server.

For the details of the setters in v3:

- **D. One exception class.** Both setters raise `ArgumentError` for an
  argument that cannot be a server (empty, too long, not an address), and
  `RuntimeError` only for a failure of nginx. This changes what both setters
  raise for some arguments: the stream setter for an empty or too long
  string, both for a string that nginx cannot parse. A behavior change of
  3.0.0.
- **E. No blocking resolution.** The HTTP setter sets `no_resolve`, as the
  stream setter does, and raises for a host name. A script that needs a name
  then gives an address that it got another way; the plan has no row that
  exposes nginx's resolver to scripts yet, and the `resolve` parameter of a
  server needs a zone, which option A refuses. This changes what the HTTP
  setter accepts, a behavior change of 3.0.0.

## 4. Questions for the owner, with recommendations

1. `master` (2.7.3): refuse a zone upstream in both setters (option A)?
   Recommended: yes. The zone case with several workers cannot work with the
   current design, the change is small, and it ends a case that the 2.7.2
   release notes already call unsupported. It is a behavior change of 2.7.3
   with an entry under "Behavior changes: read before upgrading", which also
   names `worker_processes 1`. Options 0 and B are not recommended: 0 leaves
   the case, and B conflicts with `resolve` and needs more code than the 2.x
   policy asks for. **Decided on 2026-10-29: option A in 2.7.3** (the
   option "2.7.3で例外にする (推奨)" of a session's question).
2. v3: keep the two setters with option A, document their per-worker
   meaning, and point scripts that choose a server per request at the
   balancer API of the plan once it exists (option C)? Recommended: yes; the
   hook and the API are already planned for the agent proxy, so no new design
   is needed.
   **Decided on 2026-10-30: yes** (the option "そうする (推奨)" of a
   session's question).
3. v3: options D and E? Recommended: yes for both, as entries of
   `docs/releases/v3.0.0.md`. E follows the design principle "No blocking"
   of `AGENTS.md`.
   **Decided on 2026-10-30: yes for both** (the options "そろえる (推奨)" for
   D and "例外にする (推奨)" for E of a session's question, and
   "すごい！両方進めて！" to the explicit proposal of both). The sessions read
   D as covering the value of the argument, because its text speaks of
   arguments and question 2 keeps option A; neither answer names the zone. So
   a setter called on an upstream with a `zone` keeps the `RuntimeError` of
   option A (#652), which is about the upstream.

The owner decided two more changes of the setters for 2.7.3 on 2026-10-29,
in the same question: both raise `TypeError` for an argument that is not a
String, recorded as a behavior change ("直していいけどその仕様前提で書いてる人もいるから振る舞いの変更としてちゃんとリリースに書くようにしてね"),
and `Nginx::Upstream.new` and `Nginx::Stream::Connection.new` find the
upstream by its whole name, not by a name that starts with the argument (the
option "2.7.3で完全一致にする (推奨)"). Step 1 makes the three changes.

## 5. Steps

| Step | Change | Branch | State |
|---|---|---|---|
| 1 | Option A in both setters, `TypeError` for an argument that is not a String, and the lookup of the upstream by its whole name: a test commit, then the fix commit, with the entries in `docs/releases/v2.7.3.md` and `.ja.md` | `master` (reaches `next` by the merge) | Done: #652, in `next` by #658 |
| 2 | The per-worker meaning of the setters in `docs/class_and_method/`, and a pointer to the balancer API | `next` | The meaning is done: #648. The pointer waits for the balancer API, in the row "Ruby balancer API" of `docs/proposals/v3-plan.md` |
| 3 | Options D and E, with their entries in `docs/releases/v3.0.0.md` | `next` | Done: #680 |
