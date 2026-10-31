#!/usr/bin/env python3
"""Select runtime CI from an allowlist, never from a denylist.

PRs compare their synthetic merge with its first parent. Pushes compare both
endpoints. Renames stay delete+add, so moving runtime code into docs cannot hide
its old path. This selects runtime jobs only: site/examples retain their checks.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess

RECORDS = {'AGENTS.md', 'CLAUDE.md', 'docs/HANDOFF.md'}
ROOT_DOCS = {'README.md', 'CONTRIBUTING.md', 'SECURITY.md'}


def classify(changes):
    categories = set()
    runtime = not changes
    for path, before, after in changes:
        parts = path.split('/')
        safe = (path and not path.startswith('/') and
                all(p not in ('', '.', '..') for p in parts) and
                not any(ord(c) < 32 for c in path) and
                before in ('000000', '100644') and after in ('000000', '100644'))
        if not safe:
            category = 'unknown'
        elif path in RECORDS:
            category = 'records'
        elif path in ROOT_DOCS or (path.startswith('docs/') and path.endswith('.md')):
            category = 'content'
        elif path.startswith('site/src/content/') and path.endswith(('.md', '.mdx')):
            category = 'site-content'
        elif path.startswith('site/'):
            category = 'site'
        elif path.startswith('examples/'):
            category = 'examples'
        else:
            category = 'runtime-or-unknown'
        categories.add(category)
        runtime |= category in ('unknown', 'runtime-or-unknown')
    return {'runtime': bool(runtime), 'categories': sorted(categories)}


def changed_files(base, head, cwd=None):
    raw = subprocess.check_output(['git', 'diff', '--raw', '-z', '--no-renames',
                                   base, head, '--'], cwd=cwd)
    fields = raw.decode('utf-8', errors='surrogateescape').split('\0')
    if fields[-1] != '':
        raise ValueError('unterminated git diff')
    fields.pop()
    if len(fields) % 2:
        raise ValueError('invalid git diff')
    changes = []
    for index in range(0, len(fields), 2):
        metadata, path = fields[index:index + 2]
        values = metadata.split()
        if len(values) != 5 or not values[0].startswith(':'):
            raise ValueError('invalid git raw record')
        changes.append((path, values[0][1:], values[1]))
    return changes


def gate(scope_result, runtime, build, soak, files):
    expected = {'true': 'success', 'false': 'skipped'}.get(runtime)
    return (scope_result == 'success' and files == 'success' and
            expected is not None and build == expected and soak == expected)


def event_scope(env):
    event = env.get('EVENT_NAME')
    if event == 'pull_request':
        # Missing second parent means this is not the required merge checkout.
        subprocess.check_call(['git', 'rev-parse', '--verify', 'HEAD^2'],
                              stdout=subprocess.DEVNULL)
        return classify(changed_files('HEAD^1', 'HEAD'))
    before = env.get('PUSH_BEFORE', '')
    head = env.get('PUSH_SHA', '')
    if (event == 'push' and env.get('REF_TYPE') == 'branch' and
            re.fullmatch(r'[0-9a-f]{40}', before) and int(before, 16) and
            re.fullmatch(r'[0-9a-f]{40}', head)):
        if subprocess.call(['git', 'cat-file', '-e', before + '^{commit}'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
            subprocess.check_call(['git', 'fetch', '--no-tags', 'origin', before])
        return classify(changed_files(before, head))
    return {'runtime': True, 'categories': ['full-event']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate', action='store_true')
    args = parser.parse_args()
    if args.gate:
        keys = ('SCOPE_RESULT', 'RUNTIME', 'BUILD_RESULT', 'SOAK_RESULT', 'FILES_RESULT')
        values = [os.environ.get(key, '') for key in keys]
        print(json.dumps(dict(zip(keys, values))))
        return 0 if gate(*values) else 1
    try:
        result = event_scope(os.environ)
    except (subprocess.CalledProcessError, OSError, ValueError):
        # Missing history, unexpected diff and retrieval errors never mean no work.
        result = {'runtime': True, 'categories': ['classification-fallback']}
    print(json.dumps(result, sort_keys=True))
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as stream:
            stream.write('runtime=' + str(result['runtime']).lower() + '\n')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as stream:
            stream.write('## Runtime CI scope\n\n' + json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
