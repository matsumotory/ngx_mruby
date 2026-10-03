# Security Policy

## Supported versions

| Version | Where | Status |
|---|---|---|
| Latest 2.x release | `master` (until v3.0.0 is released), `v2.x`, `v2.*` tags | Supported |
| v3 pre-releases (`v3.0.0-alpha.N`, `-beta.N`, `-rc.N`) | `next` | Best effort |
| Older 2.x minor releases, 1.x | `v2.*`/`v1.*` tags | Not supported: upgrade to the latest 2.x release |

Security fixes for 2.x are released as a new 2.x patch release. How long 2.x stays
supported after v3.0.0 will be announced in the README and in this file.

## Reporting a vulnerability

Please do **not** report security vulnerabilities through public GitHub issues,
pull requests or discussions.

Report them privately with GitHub's private vulnerability reporting:
open the repository's **Security** tab and click **Report a vulnerability**
(<https://github.com/matsumotory/ngx_mruby/security/advisories/new>).

If that form is not available to you, open a public issue that only asks for a
private contact channel. Do not include any details of the problem in it.

## What to include

- The ngx_mruby version or commit, the nginx version and its configure options,
  the OpenSSL version, and any changes to `build_config.rb`
- A minimal `nginx.conf` and the Ruby code involved
- Steps to reproduce, and the expected and actual behavior
- The impact as you understand it (for example crash, memory disclosure,
  denial of service) and the conditions an attacker needs
- Any backtrace, sanitizer or valgrind output
- Whether the issue is already known to others, and how you would like to be
  credited

## What to expect

ngx_mruby is maintained by volunteers, so there is no guaranteed response time.
We will acknowledge your report, keep you informed in the advisory, and may ask
for more details. If you have not heard back after two weeks, please post a
reminder in the same advisory.

## Coordinated disclosure

- The fix is prepared privately (in the advisory's temporary private fork) and
  released as a new version.
- The advisory is published when the fixed release is available, with a CVE
  where appropriate. Reporters are credited unless they prefer otherwise.
- Please keep the issue confidential until the advisory is published, or until we
  agree on a disclosure date with you.

Vulnerabilities in bundled or third-party components (mruby, nginx,
ngx_devel_kit, mrbgems) should also be reported to their upstream projects. If
such an issue affects ngx_mruby builds, please let us know as well.
