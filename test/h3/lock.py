"""Writes test/h3/requirements.txt from test/h3/requirements.in.

    python3 test/h3/lock.py

Each line of requirements.in pins one package (name==version, with an
optional environment marker after ";"). The output has the same lines, each
with the sha256 of every file that PyPI lists for that version, so that
`pip install --require-hashes` installs only those files. The hashes come
from the JSON API of PyPI (https://pypi.org/pypi/<name>/<version>/json).
"""

import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def hashes(name, version):
    url = "https://pypi.org/pypi/%s/%s/json" % (name, version)
    with urllib.request.urlopen(url, timeout=60) as res:
        release = json.load(res)
    digests = sorted({f["digests"]["sha256"] for f in release["urls"]})
    if not digests:
        sys.exit("lock.py: PyPI lists no files for %s %s" % (name, version))
    return digests


def main():
    out = [
        "# Written by `python3 test/h3/lock.py` from requirements.in; do not edit.",
        "# test.sh installs these with pip --require-hashes.",
    ]
    with open(os.path.join(HERE, "requirements.in")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            spec = line.split(";")[0].strip()
            name, version = spec.split("==")
            out.append(line + " \\")
            digests = hashes(name, version)
            for i, digest in enumerate(digests):
                end = "" if i == len(digests) - 1 else " \\"
                out.append("    --hash=sha256:%s%s" % (digest, end))
    with open(os.path.join(HERE, "requirements.txt"), "w") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
