# Release notes

Each release of ngx_mruby has a file in this directory, `vX.Y.Z.md`, that says
what changed in it. Its first section, "Behavior changes: read before
upgrading", lists every change that makes the same `nginx.conf`, Ruby script
or build behave differently from the previous release, why it changed, who
is affected, and what to do. Before you upgrade, read that section in every
file newer than the version you run. `vX.Y.Z.ja.md`, next to the file, has
the same notes in Japanese. A file that has no Japanese version yet gets one
from the next pull request that adds to it or edits it (see "Who writes the
entries, and when").

日本語版のリリースノートは、同じディレクトリの`vX.Y.Z.ja.md`です。日本語版がまだ無いときは、英語版の`vX.Y.Z.md`を読んでください。

Releases up to v2.7.0 have no file here: their
[GitHub release pages](https://github.com/matsumotory/ngx_mruby/releases) list
the merged pull requests.

The owner decided on 2026-10-04 that every entry under "Behavior changes:
read before upgrading" also says why the fix had to change the behavior, in a
form that convinces a reader who built on the old behavior, and that the
release notes are written precisely, in English and in Japanese. The "Why it
changed" lines of the template, the Japanese file, the GitHub release body
and the check before the tag below are how the sessions carry that out.

## What counts as a behavior change

A behavior change is a difference from the previous release that a
configuration, a Ruby script or a build can observe, and that someone may have
built on. The list below gives examples and is not complete: any such
difference counts.

- the status, headers or body of a response;
- the data that an `mruby_stream` handler sends, and when it closes the
  connection;
- what a Ruby method returns or raises, and which classes and methods exist;
- which handler runs, in which phase and order, and what its return value does;
- the value of an nginx variable set by `mruby_set`, `mruby_set_code` or
  `Nginx::Var`, as other directives and `log_format` read it;
- whether `nginx -t` accepts a configuration, and what a directive's arguments mean;
- lines in `error.log` at level `notice` and above that are added, removed or
  logged at another level, because operators alert on them;
- a build requirement that is raised (for example a newer minimum OpenSSL), a
  stable nginx line or a platform that is no longer supported (see "Supported
  nginx versions" below), a build option that is removed or changes meaning,
  and a change of the bundled mruby or of the mrbgems that the default
  `build_config.rb` includes.

An addition that leaves every existing configuration, script and build
behaving as before is not a behavior change: for example a new directive, a
new Ruby class or method, or a new value that a directive accepts. It goes
under "New features" (additive build changes go under "Build and test
changes").

The owner said on 2026-10-29:
「修正対象をしようとして使ってた場合に変更で変わる場合はノート必須」 ("when
someone used the behavior being fixed as if it were specified, and the fix
changes it, the note is required"; 「しようとして」 reads as 「仕様として」, "as
the specification"). The sessions read it as follows. A bug fix is a
behavior change when a configuration or script that used the code being
fixed sees a difference after the fix: for example, a response whose status
or headers differ, or a method that returned a value or accepted an argument
and now raises. This holds also when the old behavior was the defect itself,
because someone may have built on it. A fix is not a behavior change in one
case only: it removes a crash, a hang or a leak, and nothing else that a
configuration or script sees changes, so no one could have built on the old
behavior. A fix that turns some uses into an exception or a new result while
it removes a crash for others changes those uses, and is one. When in doubt,
record it as a behavior change.

"Previous release" means the last release tag `vX.Y.Z`, not the previous
commit. Pre-release tags (`-alpha.N`, `-beta.N`, `-rc.N`) are not releases in
this sense: `v3.0.0.md` compares 3.0.0 with the latest 2.x release. A behavior
that was added and then changed again between two releases was never
released: edit its entry instead of adding a second one.

Supported nginx versions: ngx_mruby supports the nginx mainline and stable
lines ([README.md](../../README.md)), built as [`docs/install/`](../install/)
describes. Moving from a superseded mainline version to a newer one (in CI or
in `nginx_version`) does not drop a supported version: record it under "Build
and test changes". Dropping support for a stable line (an even minor version,
such as 1.28) or for a platform is a behavior change.

Changes to tests, CI or documentation only, and refactoring with no observable
difference, need no entry under "Behavior changes: read before upgrading".
Test or CI changes that contributors or packagers need to know (for example
new test ports) go under "Build and test changes"; other test or CI changes,
documentation changes and refactoring need no entry at all.

## Who writes the entries, and when

- The pull request that makes a change also records it, in the same pull
  request:
  - a behavior change goes under "Behavior changes: read before upgrading".
    This includes the build changes in the last item of the list above; they
    may also be listed under "Build and test changes";
  - an addition to the directives, the Ruby API or the handlers that leaves
    existing configurations and scripts behaving as before goes under "New
    features";
  - other fixes go under "Fixes";
  - additive build changes (a newly supported nginx version, a new build
    option), and test or CI changes that contributors or packagers need to
    know (for example new test ports), go under "Build and test changes".
- The first pull request of a release cycle that has something to record
  creates the file and its Japanese version from the template below. Later
  pull requests of the cycle add to both, so the files always describe the
  version that will be tagged next.
- A release file that has no Japanese version yet, because it was created
  before the Japanese version was required, gets one from the first pull
  request that adds to it or edits it. That pull request translates the
  whole English file, the entries of earlier pull requests included, so that
  the two files have the same entries.
- The same pull request updates [`docs/directives/`](../directives/),
  [`docs/class_and_method/`](../class_and_method/) or
  [`docs/install/`](../install/) so that they describe the new behavior. The
  release notes say what changed; those docs say how it works now.
- In review ([AGENTS.md](../../AGENTS.md#review-and-merge)), a behavior change
  without its entry under "Behavior changes: read before upgrading" is a
  "must fix" and blocks the merge. So is such an entry that lacks a line of
  the template ("Why it changed" included), and so is one whose Japanese
  version is missing or says something other than the English entry. A
  reviewer may supply the Japanese text to an author who does not write
  Japanese. A missing "New features", "Fixes" or "Build and test changes"
  entry is a "should fix", and so is a missing Japanese version of one, or
  one that says something other than the English entry. The review checks
  the entries of the pull request itself. When that pull request creates the
  Japanese file of a release file created before the Japanese version was
  required (see above), a Japanese version of an earlier entry that is
  missing, or says something other than the English entry, is rated like one
  of the pull request's own: a "must fix" under "Behavior changes: read
  before upgrading", a "should fix" in the other sections. An earlier entry
  that lacks "Why it changed" is left to "Before the tag" below and is not a
  finding of that pull request.
- Before each tag, a pull request checks the file against every pull request
  merged since the previous release (see "Before the tag" below).

## File names

The file is named after the version that will be released. If the release
is published under a different version, rename the file and its Japanese
version with `git mv` before the release.

- `master`, before v3 is promoted: the next 2.x patch release. After the tag
  `v2.<minor>.<patch>`, the file is `v2.<minor>.<patch+1>.md`.
- `next`: one file, `v3.0.0.md`, for the whole 3.0.0 cycle, including its
  alpha, beta and rc pre-releases. It compares 3.0.0 with the latest 2.x
  release. Changes that reach `next` by merging `master` are recorded in the
  2.x file of the release that ships them, not again in `v3.0.0.md` (if 3.0.0
  is tagged before that 2.x release, copy the entry into `v3.0.0.md`).
- After v3 is promoted, `master` names its file after the next 3.x release,
  and `v2.x` after the next 2.x release.

Users who upgrade from 2.x to 3.0.0 read the 2.x files newer than their
version, then `v3.0.0.md`.

The Japanese version of `vX.Y.Z.md` is `vX.Y.Z.ja.md` in the same directory,
for example `v2.7.1.ja.md` next to `v2.7.1.md`. It is a translation of the
English file, which is the source: it has the same sections and the same
entries in the same order, and each entry says what its English entry says
(see "The Japanese file" below). Everything in this README about creating,
adding to, editing, moving, copying or renaming the file of a release or its
entries applies to the Japanese file as well, in the same pull request.

The v3 migration guide (planned in `docs/proposals/v3-plan.md` on `next`) is
built on the "Behavior changes" section of `v3.0.0.md`: it covers every entry
of that section, links to it, and adds the steps and examples. It does not
keep a second list, so each behavior change of 3.0.0 is recorded once, in
`v3.0.0.md`.

## Template

Copy this into `docs/releases/vX.Y.Z.md`. Keep every section, and write
"None." in a section that has no entries. For `docs/releases/vX.Y.Z.ja.md`,
copy it with the Japanese headings and labels of "The Japanese file" below.

```markdown
# ngx_mruby vX.Y.Z

## Behavior changes: read before upgrading

### <The change, in one line> (#<pull request>)

- Before: <what a configuration, script or build observed on the previous release>
- Now: <what it observes on this release>
- Why it changed:
  - The defect: <what the old behavior got wrong, with the issue or pull request that reports it>
  - Why the old behavior could not be kept: <what keeping it would have left
    broken; in an entry with "The reason:", what keeping it would have cost>
  - What the documentation promised: <what the docs said about it before this
    release, with a link, or that they described the old behavior or said nothing>
- Affected: <the directives, handlers, methods, configurations or builds that see the difference>
- What to do: <the change to make, or "nothing", with the reason>

## New features

- <The addition, in one line> (#<pull request>)

## Fixes

- <The fix, in one line> (#<pull request>)

## Build and test changes

- <A newly supported nginx version, a new build option, a test or CI change> (#<pull request>)

## Upgrading

<Supported nginx versions, whether rebuilding the module is enough, and the
"What to do" lines above in one list.>
```

A raised build requirement, a dropped stable nginx line or platform, a removed
build option and a change of the bundled mruby or of the default mrbgems go
under "Behavior changes: read before upgrading", not only under "Build and
test changes".

Write "Why it changed" for an operator who built on the old behavior and asks
why the release did not keep it. Each of its three lines gives evidence that
the reader can check, not only the statement that the old behavior was wrong:

- The defect: what the old behavior got wrong, with the issue or pull request
  that reports it. An entry that does not fix a defect (a raised build
  requirement, a dropped nginx line or platform, an update of the bundled
  mruby or of the default mrbgems, or a change that v3 makes on purpose)
  writes "The reason:" in this line instead, with the reason for the change.
- Why the old behavior could not be kept: why fixing the defect needed the
  difference that "Now" describes, that is, what keeping the old behavior
  would have left broken. In an entry that writes "The reason:", this line
  says what keeping the old behavior would have cost, for example the fixes
  that an older dependency no longer gets, or the goal of the v3 change that
  the old behavior would not meet.
- What the documentation promised: what `docs/`, or the nginx documentation
  for behavior that nginx defines, said about it before this release, with a
  link. This is usually the behavior that the fix brings back. If the
  documentation described the old behavior, or said nothing about it, say so.

An entry may end with one more line, "Not changed by this release:", that
names a related behavior that stays as it was, when readers may expect the
change to cover it. The line is optional and is not part of the template.

## The Japanese file

`vX.Y.Z.ja.md` is written from the English text of `vX.Y.Z.md`, entry by
entry. It follows these conventions:

- The headings, the line labels and "None." are the ones in the table below,
  so that the two files can be compared entry by entry and label by label.
  A label that the table does not list, such as "Unchanged:" inside an
  "Affected" line, gets a Japanese label of the author's choice, followed by
  the full-width colon.
- No space is typed between Japanese characters and Latin letters, digits or
  code spans.
- Japanese punctuation: 、 and 。, 「」 around quoted words, and the
  full-width colon ： after a line label.
- No em dash (U+2014), kome mark (U+203B) or emoji.
- What the English text explains in parentheses becomes a clause or a
  sentence of its own. Parentheses stay only around identifiers, such as the
  pull request number in `(#566)`, and around an abbreviation at its first
  use, after the full name.
- Code, directive, class and method names, `error.log` lines, commands, file
  paths, issue and pull request numbers and links stay as they are in the
  English text.
- Each paragraph and each list item is one line of the source, with no `<br>`
  or `<wbr>`. How body text wraps on a narrow screen (Japanese wraps by
  character) is up to what renders it, GitHub or the ngx.mruby.org site, not
  up to the Markdown. A line break inside a Japanese paragraph also reaches
  the HTML that GitHub renders from the file, and Chromium shows it as a
  space between the two characters.

| In `vX.Y.Z.md` | In `vX.Y.Z.ja.md` |
|---|---|
| `# ngx_mruby vX.Y.Z` | `# ngx_mruby vX.Y.Z` |
| `## Behavior changes: read before upgrading` | `## アップグレードの前に読む挙動の変更` |
| `- Before:` | `- 変更前：` |
| `- Now:` | `- 変更後：` |
| `- Why it changed:` | `- 変更の理由：` |
| `- The defect:` | `- 不具合：` |
| `- The reason:` | `- 背景：` |
| `- Why the old behavior could not be kept:` | `- 前の挙動を残せなかった理由：` |
| `- What the documentation promised:` | `- ドキュメントが示していた挙動：` |
| `- Affected:` | `- 影響の範囲：` |
| `- What to do:` | `- 必要な対応：` |
| `- Not changed by this release:` | `- このリリースで変わらない挙動：` |
| `## New features` | `## 新機能` |
| `## Fixes` | `## 不具合の修正` |
| `## Build and test changes` | `## ビルドとテストの変更` |
| `## Upgrading` | `## アップグレード` |
| `None.` | `ありません。` |

## Before the tag

Before a release is published, a pull request checks the file and its
Japanese version against what was merged. It lists every pull request merged
into the branch since the previous release (`git log --first-parent --merges <previous tag>..origin/<branch>`),
confirms for each one that it has its entry or changes nothing that a
configuration, script or build can observe, and adds the entries that are
missing. It completes each entry under "Behavior changes: read before
upgrading" that lacks a line of the template ("Why it changed" included). It
creates the Japanese file by translating the English one if the release has
none yet. Otherwise it compares the Japanese file with the English one: the
same sections, and the same entries in the same order, each saying what its
English entry says. It adds the Japanese entries that are missing and
corrects those that differ.
Its body lists each pull request with the section of its entry, or "no entry"
and the reason, and says that the two files were compared. This catches pull
requests merged before this convention, pull requests whose author did not
follow it, and entries that a review missed. The same pull request renames
both files if the release will be a different version.

The check pull request has the label `full-matrix`, given when it is opened
(`gh pr create --draft --label full-matrix`; `gh label create full-matrix`
adds the label once, if the repository has none), so that its run of `test.yml`
builds every cell of the build matrix, where other pull requests run four
cells ("Which jobs a run starts" in [docs/test/README.md](../test/README.md)).

On `next`, the range starts at the previous pre-release tag, and for the first
pre-release at the latest 2.x release tag. A merge of `master` into `next`
brings the pull requests merged into `master` with it
(`git log --first-parent --merges <merge>^1..<merge>^2` lists them). For such a
merge, the check confirms that each of those pull requests has its entries in
the 2.x file (see "File names"), and before the 3.0.0 tag it copies into
`v3.0.0.md` the entries whose 2.x release is not tagged yet.

The session publishes the release at the merge commit of the check pull
request, after the owner has given the go-ahead for that release (the
session asks for it with the release notes ready;
`gh release create <tag> --target <commit> --title <title> --notes-file <body>`
creates the release and its tag). Pull requests
merged after it ship in the following release, and the check for that release
moves their entries to that release's file. If the release is published at a
later commit instead, the check is repeated for the pull requests merged
after the check pull request. A release that ships a security fix follows the order in
"Security fixes" below.

## The GitHub release

When the session publishes a release, its body carries both texts, English
first: the "Behavior changes: read before upgrading" section copied from the
English file ("None." when there are none), then the same section copied from
the Japanese file, then links to the two files. The body does not copy the
list of pull requests that GitHub generates; the release notes name the pull
requests. A pre-release on `next` copies, from both files, the
entries added or changed since the previous pre-release;
`git diff <previous pre-release tag> <new tag> -- docs/releases/v3.0.0.md docs/releases/v3.0.0.ja.md`
shows them. The first pre-release copies the whole section. Agents prepare
the files and, after the owner's go-ahead, publish the release (see
[AGENTS.md](../../AGENTS.md#branches-and-pull-requests)); the owner publishes
the advisory.

## Security fixes

A security fix is prepared in the advisory's private fork and released as a
new version (see [SECURITY.md](../../SECURITY.md)). Its entries, in both
files, are written in the same private pull request as the fix, so that the
tagged files and the release body have them:

- The entries are neutral: they name the affected component and say what is
  observable now. Nothing in them tells how to exploit or reproduce the
  problem, or says that it is a vulnerability.
- If the fix changes behavior, its "Behavior changes" entry says before, now,
  why it changed, what is affected and what to do, in the same neutral terms.
  "Why it changed" names the defect only as the difference that "Before"
  describes; the advisory id, added when the advisory is published (below),
  points to the details.
- The advisory draft is written in English, and after the English sections
  it has the same content in Japanese. The owner said on 2026-10-29:
  「日本語でも後半でいいのでしっかりかいておいてほしい、今後は」
  ("write it carefully in Japanese too, in the second half; from now on").
- When the owner publishes the advisory, a pull request adds the advisory id
  (`GHSA-xxxx-xxxx-xxxx`) to the entries in both files, and the session adds it
  to both texts of the release body. That pull request may also list the
  fixes that the advisory covers apart from the other fixes in "Fixes", and
  may give the cause of the defect in "Why it changed", within what the
  published advisory and the public fix in `src/` disclose.

A release that ships a security fix is prepared in this order, so that the fix
is public for as short a time as possible before the release:

1. The check pull request ("Before the tag") is merged before the fix. It
   covers the pull requests merged until then; the fix's private pull request
   carries its own entries.
2. The owner merges the fix from the advisory's private fork ("Merge pull
   request(s)" on the advisory), and the session publishes the release at the
   fix's merge commit right after. This is the exception to publishing at the
   merge commit of the check pull request. If
   another pull request is merged between the two, its entries are checked
   before the fix is merged.

Until the advisory is published, nothing in the public repository mentions
the vulnerability (see [AGENTS.md "Security"](../../AGENTS.md#security)).
