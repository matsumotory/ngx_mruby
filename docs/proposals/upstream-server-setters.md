# Proposal: the upstream server setters with a `zone`, and their form in v3

Status: proposed on 2026-10-29. Next step: the owner answers the three
questions of section 4 (by 2026-11-05); then step 1 of section 5 goes to
`master` and steps 2 and 3 become rows of the plan. Written on 2026-10-29
from `master` at `c6d3b3b9b` (2.7.2 and #645), `next` at `67ad9b919`, and
the source of nginx 1.31.8 (the version in `nginx_version`). It follows the
review of #624, which left three points for later: the stream setter takes
no lock on the peer, the two setters raise different exception classes for
the same argument, and their argument checks were not documented (the last
point is #648 on `master`).

## 1. What the setters do in 2.7.2

`Nginx::Upstream#server=` (HTTP) and `Nginx::Stream::Connection#upstream_server=`
(stream) change the address of an `upstream {}` block that has exactly one
server.

- Both change the round-robin peer itself, which every later request or
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
- The HTTP setter takes the read lock of the peers and the lock of the peer
  while it changes the peer (`ngx_http_upstream_rr_peers_rlock` and
  `ngx_http_upstream_rr_peer_lock`, `ngx_http_mruby_upstream.c:232-241`); the
  stream setter takes no lock. These locks do something only when the peers
  are in a shared memory zone (`peers->shpool`,
  `src/http/ngx_http_upstream_round_robin.h:135-165` of nginx). Without a
  zone, a worker runs one request at a time on its own peers, and neither
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
both setters say that only the case without a zone is handled.

nginx also manages the peers of a zone upstream itself: since nginx 1.27.3
(CHANGES, 26 Nov 2024) a server of an upstream block can have the `resolve`
parameter, and nginx then replaces the peers when the name resolves to other
addresses. A module that changes the name and address of such a peer in
place works against that. A lock alone, which the review of #624 asked for
in the stream setter, does not make the zone case correct, because the
stored name and sockaddr are still in the memory of one worker.

## 3. Options

- **A. Refuse an upstream with a zone.** Both setters raise before they
  change anything when `peers->shpool` is set, with a message that names
  the zone. Small, and the same on `master` and `next`. A configuration that
  uses a setter on a zone upstream today gets an exception where it got a
  peer that only one worker could use.
- **B. Store the name and the sockaddr in the zone's slab.** The setters
  allocate in `peers->shpool` under the write lock of the peers and free the
  old values, as the zone module does for its own copies. This keeps the
  per-worker meaning of the setters for a shared peer, which changes the
  upstream for every worker at once, and still conflicts with nginx's own
  replacement of the peers under `resolve`.
- **C. Choose the peer per request in v3.** The plan already has an
  upstream peer hook (the Pillar B row "Upstream peer hook", and the row
  "Ruby balancer API: `mruby_upstream_balancer` in `upstream {}`" that builds
  on it, in `docs/proposals/v3-plan.md` on `next`), which chooses the peer
  for each attempt of a request without changing the configured peers. That
  is the form in which a script picks a server for one request, as
  `ngx.balancer.set_current_peer` does in OpenResty's `balancer_by_lua*`.
  With it, the two setters keep their per-worker meaning only for code that
  wants it.

For the details of the setters in v3:

- **D. One exception class.** Both setters raise `ArgumentError` for an
  argument that cannot be a server (empty, too long, not an address), and
  `RuntimeError` only for a failure of nginx. This changes what the stream
  setter raises, a behavior change of 3.0.0.
- **E. No blocking resolution.** The HTTP setter sets `no_resolve`, as the
  stream setter does, and raises for a host name; a script that needs a name
  resolves it with nginx's resolver, which a later row of the plan can
  expose, or uses the peer hook of C with an upstream that has `resolve`.
  This changes what the HTTP setter accepts, a behavior change of 3.0.0.

## 4. Questions for the owner, with recommendations

1. `master` (2.7.3): refuse a zone upstream in both setters (option A)?
   Recommended: yes. The zone case cannot work with the current design, the
   change is small, and it ends a case that the 2.7.2 release notes already
   call unsupported. It is a behavior change of 2.7.3 with an entry under
   "Behavior changes: read before upgrading". Option B is not recommended:
   it conflicts with `resolve` and needs more code than the 2.x policy asks
   for.
2. v3: keep the two setters with option A, document their per-worker
   meaning, and point scripts that choose a server per request at the peer
   hook and the balancer API of the plan (option C)? Recommended: yes; the
   hook is already planned for the agent proxy, so no new design is needed.
3. v3: options D and E? Recommended: yes for both, as entries of
   `docs/releases/v3.0.0.md`. E follows the design principle "No blocking"
   of `AGENTS.md`.

## 5. Steps

| Step | Change | Branch | State |
|---|---|---|---|
| 1 | Option A in both setters: a test commit (a `zone` upstream, both setters raise and the peer is unchanged), then the fix commit, with the entry in `docs/releases/v2.7.3.md` and `.ja.md` | `master` (reaches `next` by the merge) | Waits for question 1 |
| 2 | The per-worker meaning of the setters in `docs/class_and_method/`, and a pointer to the peer hook and the balancer API | `next` | Waits for question 2 and for the hook |
| 3 | Options D and E, with their entries in `docs/releases/v3.0.0.md` | `next` | Waits for question 3; can start before the hook |
