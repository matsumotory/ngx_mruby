#!/usr/bin/env python3
"""Check relative links and anchors in Markdown files.

Usage: check_links.py REPO_ROOT FILE[=AS_PATH] ...

FILE is read; links are resolved as if the file were at AS_PATH (relative to
REPO_ROOT), so a planted copy can live outside the repository. Exits 1 if any
relative link points to a missing path, a missing heading anchor, or a line
number past the end of the file. External links (scheme://, mailto:) are
counted and skipped.
"""
import os
import re
import sys

LINK = re.compile(r'(?<!!)\[(?:[^\[\]]|\[[^\]]*\])*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
IMAGE = re.compile(r'!\[[^\]]*\]\(([^)\s]+)\)')
FENCE = re.compile(r'^\s*(```|~~~)')
CODE_SPAN = re.compile(r'`[^`]*`')


def strip_code(text):
    out, in_fence = [], False
    for line in text.split('\n'):
        if FENCE.match(line):
            in_fence = not in_fence
            out.append('')
            continue
        out.append('' if in_fence else CODE_SPAN.sub('', line))
    return out


def slugs(path):
    """GitHub heading anchors of a Markdown file."""
    seen, result = {}, set()
    in_fence = False
    with open(path, encoding='utf-8') as f:
        for line in f:
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            m = re.match(r'^(#{1,6})\s+(.*?)\s*#*\s*$', line)
            if not m:
                continue
            text = m.group(2)
            text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', text)  # links -> text
            text = re.sub(r'<[^>]+>', '', text)                    # inline html
            s = text.strip().lower()
            s = re.sub(r'[^\w\- ]', '', s)                          # keep letters, digits, _, -, space
            s = s.replace(' ', '-')
            n = seen.get(s, 0)
            seen[s] = n + 1
            result.add(s if n == 0 else '%s-%d' % (s, n))
    return result


def check(root, src, as_path):
    with open(src, encoding='utf-8') as f:
        lines = strip_code(f.read())
    base = os.path.dirname(os.path.join(root, as_path))
    broken, checked, external = [], 0, 0
    for lineno, line in enumerate(lines, 1):
        targets = [m.group(1) for m in LINK.finditer(line)] + [m.group(1) for m in IMAGE.finditer(line)]
        for t in targets:
            if re.match(r'^[a-z][a-z0-9+.-]*:', t):
                external += 1
                continue
            checked += 1
            path, _, frag = t.partition('#')
            target = os.path.normpath(os.path.join(base, path)) if path else os.path.join(root, as_path)
            if not os.path.exists(target):
                broken.append((lineno, t, 'missing path %s' % os.path.relpath(target, root)))
                continue
            if not frag:
                continue
            mline = re.fullmatch(r'L(\d+)(?:-L(\d+))?', frag)
            if mline and os.path.isfile(target):
                with open(target, encoding='utf-8', errors='replace') as f:
                    count = sum(1 for _ in f)
                last = int(mline.group(2) or mline.group(1))
                if last > count:
                    broken.append((lineno, t, 'file has %d lines' % count))
                continue
            if os.path.isfile(target) and target.endswith('.md'):
                if frag not in slugs(target):
                    broken.append((lineno, t, 'no heading with anchor #%s' % frag))
            else:
                broken.append((lineno, t, 'anchor on a non-Markdown target'))
    return broken, checked, external


def main():
    root = sys.argv[1]
    total_broken = 0
    for arg in sys.argv[2:]:
        src, _, as_path = arg.partition('=')
        as_path = as_path or os.path.relpath(src, root)
        broken, checked, external = check(root, src, as_path)
        print('%s: %d relative links checked, %d external skipped, %d broken'
              % (as_path, checked, external, len(broken)))
        for lineno, t, why in broken:
            print('  line %d: %s -> %s' % (lineno, t, why))
        total_broken += len(broken)
    sys.exit(1 if total_broken else 0)


if __name__ == '__main__':
    main()
