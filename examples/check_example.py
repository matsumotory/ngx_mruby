#!/usr/bin/env python3
"""Run the steps of an example's README and compare what they print.

Usage: check_example.py [--files-only] DIR

The check of step 4 of docs/proposals/site.md, section 6: "each
examples/<use>/ starts in CI and returns the output its README states".
It reads DIR/README.md and:

- compares every fenced code block whose info string has title="FILE"
  with the file DIR/FILE, byte for byte, so that the page shows the files
  that the example runs;
- runs, in DIR and in the order of the page, every command of the
  ```console blocks (a line that starts with "$ "), with bash, except
  `git clone` and `cd`, which a reader runs before reaching DIR;
- compares the standard output of each command with the lines that follow
  it in the block, up to the next command or the end of the block. A
  command with no such lines only has to exit 0.

It prints each command with its exit status and duration, stops at the
first command that fails or prints something else than the page states,
and exits 1 then. With --files-only, it compares the files and parses the
console blocks, and runs no command. Python 3, no packages.
"""
import os
import re
import subprocess
import sys
import time

FENCE = re.compile(r'^\s*(```+|~~~+)\s*(\S*)(.*)$')
TITLE = re.compile(r'\btitle="([^"]+)"')
SKIPPED = re.compile(r'^(git clone|cd)\b')


def blocks(text):
    """The fenced code blocks of a Markdown file: (line, lang, meta, body)."""
    out, lines, i = [], text.split('\n'), 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        fence, lang, meta, start = m.group(1), m.group(2), m.group(3), i + 1
        j = start
        while j < len(lines) and not lines[j].strip().startswith(fence[0] * len(fence)):
            j += 1
        # Blocks of a list item are indented: drop the indentation of the fence
        indent = len(lines[i]) - len(lines[i].lstrip())
        body = [l[indent:] if l[:indent].strip() == '' else l for l in lines[start:j]]
        out.append((i + 1, lang, meta, body))
        i = j + 1
    return out


def steps(body):
    """The commands of a console block, each with the lines it should print."""
    result = []
    for line in body:
        if line.startswith('$ '):
            result.append([line[2:], []])
        elif result:
            result[-1][1].append(line)
        elif line.strip():
            raise ValueError(f'a console block starts with output, not with a command: {line}')
    return result


def main():
    args = sys.argv[1:]
    files_only = args[:1] == ['--files-only']
    if files_only:
        args = args[1:]
    if len(args) != 1:
        print(__doc__.strip().split('\n')[2], file=sys.stderr)
        return 2
    folder = args[0]
    readme = os.path.join(folder, 'README.md')
    problems = []
    commands = []
    for line, lang, meta, body in blocks(open(readme, encoding='utf-8').read()):
        title = TITLE.search(meta)
        if title:
            path = os.path.join(folder, title.group(1))
            if not os.path.isfile(path):
                problems.append(f'{readme}:{line}: the block shows {title.group(1)}, which the example does not have')
            elif open(path, encoding='utf-8').read() != '\n'.join(body) + '\n':
                problems.append(f'{readme}:{line}: the block titled {title.group(1)} differs from the file {path}')
        if lang == 'console':
            try:
                commands += [(line, c, out) for c, out in steps(body)]
            except ValueError as e:
                problems.append(f'{readme}:{line}: {e}')
    for p in problems:
        print(p)
    if problems:
        print(f'check_example: {len(problems)} problem(s) in {readme}')
        return 1
    if files_only:
        print(f'check_example: ok; the files shown in {readme} are those of the example, and its {len(commands)} command(s) parse (none run)')
        return 0
    run = 0
    for line, command, expected in commands:
        if SKIPPED.match(command):
            print(f'skip: {command}')
            continue
        started = time.monotonic()
        done = subprocess.run(['bash', '-c', command], cwd=folder, stdout=subprocess.PIPE, text=True)
        took = time.monotonic() - started
        print(f'$ {command}  (exit {done.returncode}, {took:.1f} s)')
        run += 1
        if done.returncode != 0:
            print(f'{readme}:{line}: the command exited {done.returncode}')
            return 1
        want = '\n'.join(expected).rstrip('\n')
        got = done.stdout.rstrip('\n')
        if expected and got != want:
            print(f'{readme}:{line}: the command printed something else than the page states')
            print(f'  expected: {want!r}')
            print(f'  printed:  {got!r}')
            return 1
    print(f'check_example: ok; {run} command(s) of {readme} ran and printed what the page states')
    return 0


if __name__ == '__main__':
    sys.exit(main())
