#!/usr/bin/env python3
"""Check the color tokens of site/src/styles/tokens.css (docs/proposals/site.md, 4.6).

The script reads tokens.css: palette A, which the owner chose on 2026-10-19
(4.12, item 1), whose light and dark values carry their OKLCH source value
in a comment after the hex value, and the code colors (--color-code-*).
For each theme it computes the WCAG 2.2 contrast ratio of every pair that
a role needs and compares the unrounded ratio with the threshold of that pair:

- 4.5:1 when a role draws text on the color or text in the color
  (WCAG 2.2 SC 1.4.3, which the proposal applies to text of every size);
- 3:1 for outlines that are a control's only cue and for the focus ring
  (SC 1.4.11).

Ratios are printed truncated to two decimals, never rounded: the WCAG
Understanding document for SC 1.4.3 says "4.499:1 would not meet the 4.5:1
threshold".

It also checks that each hex value is the conversion of its OKLCH source
(clipped to the gamut and rounded to 8-bit hex, which is what a browser
draws), that every neutral token has the hue of the page background and an
OKLCH chroma of at most NEUTRAL_MAX_CHROMA in its source value, and that the
two dark blocks (the media query and the forced dark theme) hold the same
values. Each code color must reach 4.5:1 on surface in both themes.

Usage:
  python3 site/scripts/contrast.py [--tokens FILE] [--markdown]

  --tokens FILE  read FILE instead of site/src/styles/tokens.css
  --markdown     also print the rows of the table of palette A in 4.6

It exits 1 on a failure. It needs Python 3 and no packages.
"""
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOKENS_CSS = os.path.join(HERE, '..', 'src', 'styles', 'tokens.css')

NEUTRAL_MAX_CHROMA = 0.020
LOGO_TEAL = '#40a798'

# The selector of each block of tokens.css (the same as scripts/lib/tokens.mjs)
BLOCKS = {
    'a-light': (':root', False),
    'a-dark': (':root[data-theme="dark"][data-theme-script]', False),
    'a-dark-media': (':root:not([data-theme="light"])', True),
    'home-light': (':root:has(.home)', False),
    'home-dark': (':root[data-theme="dark"][data-theme-script]:has(.home)', False),
    'home-dark-media': (':root:not([data-theme="light"]):has(.home)', True),
}

# token name: (custom property, role)
TOKENS = {
    'bg': ('--color-bg-primary', 'page'),
    'surface': ('--color-bg-tertiary', 'header, sidebar, code blocks'),
    'text': ('--color-text-primary', 'body text'),
    'text-muted': ('--color-text-muted', 'captions, code comments'),
    'accent-text': ('--color-accent-text', 'links'),
    'accent': ('--color-accent', 'focus ring, current navigation item, primary button, marks'),
    'border-strong': ('--color-border-strong', 'outlines of inputs and controls, lines of diagrams'),
    'border': ('--color-border', 'separators, outlines of round buttons, decorative'),
}
NEUTRALS = ('bg', 'surface', 'text', 'text-muted', 'border-strong', 'border')

# (foreground, background, threshold, why). Contrast is symmetric, so one
# pair covers text in a color on a background and text in the background
# color on a fill of that color.
PAIRS = [
    ('text', 'bg', 4.5, 'body text'),
    ('text', 'surface', 4.5, 'text in the header, sidebar and code blocks'),
    ('text-muted', 'bg', 4.5, 'captions'),
    ('text-muted', 'surface', 4.5, 'code comments, sidebar captions'),
    ('accent-text', 'bg', 4.5, 'links'),
    ('accent-text', 'surface', 4.5, 'links in the header and sidebar'),
    ('accent', 'bg', 4.5, 'primary button: bg text on an accent fill; focus ring (3:1)'),
    ('accent', 'surface', 4.5, 'current navigation item: accent text on surface or surface text on accent; focus ring (3:1)'),
    ('border-strong', 'bg', 3.0, 'outlines of controls'),
    ('border-strong', 'surface', 3.0, 'outlines of controls on surface'),
    ('border', 'bg', 0.0, 'decorative separator, no threshold'),
    ('border', 'surface', 0.0, 'decorative separator, no threshold'),
]

DECL = re.compile(r'(--color-[a-z-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;(?:\s*/\*\s*oklch\(\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*\)\s*\*/)?')


def parse_blocks(text):
    """The rule blocks of the file: (selector, inside @media, body)."""
    out = []
    i = 0
    depth_media = []
    text = re.sub(r'/\*(?!\s*oklch)[\s\S]*?\*/', '', text)
    while i < len(text):
        j = text.find('{', i)
        if j < 0:
            break
        head = text[i:j].strip().split(';')[-1].strip()
        if head.startswith('@'):
            depth_media.append(head.startswith('@media'))
            i = j + 1
            continue
        k = text.find('}', j)
        out.append((' '.join(head.split()), any(depth_media), text[j + 1:k]))
        i = k + 1
        # close the @media blocks that end here
        while depth_media and text[i:].lstrip().startswith('}'):
            i = text.index('}', i) + 1
            depth_media.pop()
    return out


def read_tokens(path):
    with open(path, encoding='utf-8') as f:
        blocks = parse_blocks(f.read())
    found = {}
    for name, (selector, media) in BLOCKS.items():
        for sel, m, body in blocks:
            if sel == ' '.join(selector.split()) and m == media:
                decls = {d[0]: (d[1].lower(), tuple(float(x) for x in d[2:5]) if d[2] else None)
                         for d in DECL.findall(body)}
                if decls:
                    found.setdefault(name, {}).update(decls)
    missing = [n for n in BLOCKS if n not in found]
    if missing:
        sys.exit('contrast.py: %s has no block for %s' % (path, ', '.join(missing)))
    return found


def oklch_to_hex(L, C, H):
    a = C * math.cos(math.radians(H))
    b = C * math.sin(math.radians(H))
    l_ = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    rgb = (4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
           -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
           -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_)

    def encode(c):
        c = min(max(c, 0.0), 1.0)
        return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055
    return '#' + ''.join('%02x' % round(encode(c) * 255) for c in rgb)


def hex_to_linear(h):
    h = h.lstrip('#')
    out = []
    for i in (0, 2, 4):
        c = int(h[i:i + 2], 16) / 255
        out.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return out


def luminance(h):
    r, g, b = hex_to_linear(h)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def hex_to_oklch(h):
    r, g, b = hex_to_linear(h)
    l_ = 0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b
    m_ = 0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b
    s_ = 0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b
    l_, m_, s_ = [math.copysign(abs(x) ** (1 / 3), x) for x in (l_, m_, s_)]
    L = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_
    a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_
    bb = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_
    return L, math.hypot(a, bb), math.degrees(math.atan2(bb, a)) % 360


def trunc(x):
    """Truncate to two decimals for printing: 4.4968 -> 4.49, never 4.50."""
    return '%.2f' % (math.floor(x * 100 + 1e-9) / 100)


def check_pairs(label, hexmap, failures):
    """Print every pair of PAIRS for one theme and record the failures."""
    for fg, bg, threshold, why in PAIRS:
        r = ratio(hexmap[fg], hexmap[bg])
        ok = r >= threshold
        print('  %-4s %-13s on %-8s %s:1 (needs %s) %s'
              % ('ok' if ok else 'FAIL', fg, bg, trunc(r),
                 threshold if threshold else 'none', why))
        if not ok:
            failures.append('%s %s on %s: %.6f:1, needs %s:1'
                            % (label, fg, bg, r, threshold))


def by_token(block):
    return {t: block[p][0] for t, (p, _) in TOKENS.items() if p in block}


def main():
    argv = sys.argv[1:]
    markdown = '--markdown' in argv
    path = TOKENS_CSS
    if '--tokens' in argv:
        path = argv[argv.index('--tokens') + 1]
    blocks = read_tokens(path)
    failures = []
    print('tokens: %s' % os.path.relpath(path))

    # The two dark blocks hold the same values.
    if {k: v[0] for k, v in blocks['a-dark'].items()} != {k: v[0] for k, v in blocks['a-dark-media'].items()}:
        failures.append('the blocks a-dark and a-dark-media of tokens.css differ')

    codes = sorted(p for p in blocks['a-light'] if p.startswith('--color-code-'))
    if len(codes) > 4:
        failures.append('%d code colors, more than four (4.6)' % len(codes))
    palette = {}
    for theme in ('light', 'dark'):
        block = blocks['a-%s' % theme]
        print('== palette A, %s' % theme)
        for prop, (h, src) in block.items():
            if src is None:
                failures.append('palette A %s %s has no OKLCH source value' % (theme, prop))
                continue
            conv = oklch_to_hex(*src)
            Lh, Ch, Hh = hex_to_oklch(h)
            print('  %-24s oklch(%.3f %.3f %g) -> %s (from hex: C %.4f, H %.1f)'
                  % (prop, src[0], src[1], src[2], h, Ch, Hh))
            if conv != h:
                failures.append('palette A %s %s: %s is not the conversion of its source, %s' % (theme, prop, h, conv))
        bg_hue = block['--color-bg-primary'][1][2]
        for name in NEUTRALS:
            L, C, H = block[TOKENS[name][0]][1]
            if C > NEUTRAL_MAX_CHROMA:
                failures.append('%s %s: chroma %.3f over %.3f' % (theme, name, C, NEUTRAL_MAX_CHROMA))
            if H != bg_hue:
                failures.append('%s %s: hue %g differs from bg hue %g' % (theme, name, H, bg_hue))
        palette[('a', theme)] = by_token(block)
        check_pairs('palette A %s' % theme, palette[('a', theme)], failures)

    print('== code colors on surface')
    for prop in codes:
        for theme in ('light', 'dark'):
            h = blocks['a-%s' % theme][prop][0]
            r = ratio(h, palette[('a', theme)]['surface'])
            ok = r >= 4.5
            print('  %-4s %-22s %-5s %s on surface: %s:1 (needs 4.5)'
                  % ('ok' if ok else 'FAIL', prop, theme, h, trunc(r)))
            if not ok:
                failures.append('code %s %s on surface: %.6f:1' % (prop, theme, r))

    # Homepage overrides have their own role palette. Syntax spans continue
    # using the shared Shiki colors, including its plain text and comments.
    if blocks['home-dark'] != blocks['home-dark-media']:
        failures.append('the homepage dark and dark-media blocks differ')
    for theme in ('light', 'dark'):
        block = blocks['home-' + theme]
        label = 'homepage ' + theme
        print('== ' + label)
        for prop, (h, src) in block.items():
            if src is None or oklch_to_hex(*src) != h:
                failures.append(label + ' ' + prop + ': missing or incorrect OKLCH source')
        bg_hue = block['--color-bg-primary'][1][2]
        for name in NEUTRALS:
            L, C, H = block[TOKENS[name][0]][1]
            if C > NEUTRAL_MAX_CHROMA or H != bg_hue:
                failures.append(label + ' ' + name + ': inconsistent neutral hue/chroma')
        button_ratio = ratio(block['--color-button-text'][0], block['--color-button-fill'][0])
        print('  button text on red metal fill: %s:1 (needs 4.5)' % trunc(button_ratio))
        if button_ratio < 4.5:
            failures.append('%s button text on fill: %.6f:1' % (label, button_ratio))
        # Every reading plane uses these opaque gradient stops. Check all
        # text/accent roles against every stop, not just the base canvas.
        surfaces = ('scene-deep', 'scene-face', 'scene-light', 'scene-warm', 'scene-violet')
        foregrounds = ('text-primary', 'text-muted', 'accent-text', 'code-number', 'signal-violet')
        for surface in surfaces:
            bg = block['--color-' + surface][0]
            for foreground in foregrounds:
                token = '--color-' + foreground
                fg = block.get(token, blocks['a-' + theme].get(token))[0]
                value = ratio(fg, bg)
                if value < 4.5:
                    failures.append('%s %s on %s: %.6f:1' % (label, foreground, surface, value))
        print('  all material reading planes: checked text, muted, links and route colors')
        home = by_token(block)
        check_pairs(label, home, failures)
        for prop in codes + ['--color-text-primary', '--color-text-muted']:
            h = blocks['a-' + theme][prop][0]
            r = ratio(h, home['surface'])
            print('  shared syntax %s on home surface: %s:1' % (prop, trunc(r)))
            if r < 4.5:
                failures.append('%s %s on surface: %.6f:1' % (label, prop, r))

    print('== information (not gated)')
    light = palette[('a', 'light')]
    print('  logo teal %s on light bg: %s:1; on dark bg: %s:1'
          % (LOGO_TEAL, trunc(ratio(LOGO_TEAL, light['bg'])), trunc(ratio(LOGO_TEAL, palette[('a', 'dark')]['bg']))))

    if markdown:
        print('== rows of the table of palette A in 4.6')
        for name, (prop, role) in TOKENS.items():
            cells = ['`%s`' % name, role]
            for theme in ('light', 'dark'):
                h, src = blocks['a-%s' % theme][prop]
                cells.append('`%s` oklch(%.3f %.3f %g)' % (h, src[0], src[1], src[2]))
                p = palette[('a', theme)]
                cells.append('' if name in ('bg', 'surface') else '%s / %s' % (trunc(ratio(h, p['bg'])), trunc(ratio(h, p['surface']))))
            cells.append('`%s`' % prop)
            print('| ' + ' | '.join(cells) + ' |')

    if failures:
        print('%d failure(s):' % len(failures))
        for f in failures:
            print('  ' + f)
        sys.exit(1)
    print('0 failures')


if __name__ == '__main__':
    main()
