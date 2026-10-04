#!/usr/bin/env python3
"""Check the color tokens proposed in docs/proposals/site.md, section 4.4.

The tokens below are the OKLCH source values of the proposal. For each theme
the script converts every token to sRGB (clipped to the gamut and rounded to
8-bit hex, which is what a browser draws), computes the WCAG 2.2 contrast
ratio of every pair that a role needs, and compares the unrounded ratio with
the threshold of that pair:

- 4.5:1 when a role draws text on the color or text in the color
  (WCAG 2.2 SC 1.4.3, which the proposal applies to text of every size);
- 3:1 for outlines that are a control's only cue and for the focus ring
  (SC 1.4.11).

Ratios are printed truncated to two decimals, never rounded: the WCAG
Understanding document for SC 1.4.3 says "4.499:1 would not meet the 4.5:1
threshold".

The script also checks that every neutral token has the hue of the page
background and an OKLCH chroma of at most NEUTRAL_MAX_CHROMA in its source
value. A chroma computed back from the rounded hex can be slightly higher.

Usage:
  python3 contrast.py              check, print every pair, exit 1 on a failure
  python3 contrast.py --markdown   also print the rows of the table in 4.4

Step 2 of the proposal moves this check into site/scripts/ and makes it read
the values from site/src/styles/tokens.css, together with the code
highlighting colors (CODE_COLORS).
"""
import math
import sys

HUE = 182                 # OKLCH hue of the logo teal #40a798
NEUTRAL_MAX_CHROMA = 0.020

# name: (L, C, H) in OKLCH
TOKENS = {
    'light': {
        'bg':            (0.985, 0.004, HUE),
        'surface':       (0.958, 0.008, HUE),
        'text':          (0.250, 0.020, HUE),
        'text-muted':    (0.460, 0.020, HUE),
        'accent-text':   (0.470, 0.080, HUE),
        'accent':        (0.527, 0.089, HUE),
        'border-strong': (0.600, 0.019, HUE),
        'border':        (0.890, 0.010, HUE),
    },
    'dark': {
        'bg':            (0.185, 0.010, HUE),
        'surface':       (0.225, 0.012, HUE),
        'text':          (0.930, 0.009, HUE),
        'text-muted':    (0.750, 0.013, HUE),
        'accent-text':   (0.800, 0.080, HUE),
        'accent':        (0.700, 0.090, HUE),
        'border-strong': (0.560, 0.015, HUE),
        'border':        (0.320, 0.013, HUE),
    },
}

NEUTRALS = ('bg', 'surface', 'text', 'text-muted', 'border-strong', 'border')

ROLES = {
    'bg': 'page',
    'surface': 'header, sidebar, code blocks',
    'text': 'body text',
    'text-muted': 'captions, code comments',
    'accent-text': 'links',
    'accent': 'focus ring, current navigation item, primary button',
    'border-strong': 'outlines of inputs and controls',
    'border': 'separators, decorative',
}

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

# Code highlighting colors, added in step 2: name -> {theme: (L, C, H)}.
# Each must reach 4.5:1 on surface in both themes.
CODE_COLORS = {}

LOGO_TEAL = '#40a798'


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


def main():
    markdown = '--markdown' in sys.argv[1:]
    failures = []
    hexes = {theme: {k: oklch_to_hex(*v) for k, v in t.items()}
             for theme, t in TOKENS.items()}

    for theme, t in TOKENS.items():
        print('== %s' % theme)
        for name, (L, C, H) in t.items():
            Lh, Ch, Hh = hex_to_oklch(hexes[theme][name])
            print('  %-13s oklch(%.3f %.3f %d) -> %s (from hex: C %.4f, H %.1f)'
                  % (name, L, C, H, hexes[theme][name], Ch, Hh))
        for name in NEUTRALS:
            L, C, H = t[name]
            if C > NEUTRAL_MAX_CHROMA:
                failures.append('%s %s: chroma %.3f over %.3f'
                                % (theme, name, C, NEUTRAL_MAX_CHROMA))
            if H != t['bg'][2]:
                failures.append('%s %s: hue %s differs from bg hue %s'
                                % (theme, name, H, t['bg'][2]))
        for fg, bg, threshold, why in PAIRS:
            r = ratio(hexes[theme][fg], hexes[theme][bg])
            ok = r >= threshold
            print('  %-4s %-13s on %-8s %s:1 (needs %s) %s'
                  % ('ok' if ok else 'FAIL', fg, bg, trunc(r),
                     threshold if threshold else 'none', why))
            if not ok:
                failures.append('%s %s on %s: %.6f:1, needs %s:1'
                                % (theme, fg, bg, r, threshold))
        for name, values in CODE_COLORS.items():
            r = ratio(oklch_to_hex(*values[theme]), hexes[theme]['surface'])
            print('  %-4s code %-8s on surface %s:1 (needs 4.5)'
                  % ('ok' if r >= 4.5 else 'FAIL', name, trunc(r)))
            if r < 4.5:
                failures.append('%s code %s on surface: %.6f:1' % (theme, name, r))

    light = hexes['light']
    print('== information')
    print('  logo teal %s on light bg: %s:1; on dark bg: %s:1'
          % (LOGO_TEAL, trunc(ratio(LOGO_TEAL, light['bg'])),
             trunc(ratio(LOGO_TEAL, hexes['dark']['bg']))))

    if markdown:
        print('== rows of the table in 4.4')
        for name in TOKENS['light']:
            cells = ['`%s`' % name, ROLES[name]]
            for theme in ('light', 'dark'):
                L, C, H = TOKENS[theme][name]
                h = hexes[theme][name]
                cells.append('`%s` oklch(%.3f %.3f %d)' % (h, L, C, H))
                if name in ('bg', 'surface'):
                    cells.append('')
                else:
                    cells.append('%s / %s' % (trunc(ratio(h, hexes[theme]['bg'])),
                                              trunc(ratio(h, hexes[theme]['surface']))))
            print('| ' + ' | '.join(cells) + ' |')

    if failures:
        print('%d failure(s):' % len(failures))
        for f in failures:
            print('  ' + f)
        sys.exit(1)
    print('0 failures')


if __name__ == '__main__':
    main()
