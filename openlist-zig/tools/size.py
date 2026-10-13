"""Report raw and xz -6 sizes for a binary.

`xz` is not on PATH in this environment, and Python's `lzma` with
`FORMAT_XZ, preset=6` produces byte-identical output to `xz -6`. The squashfs
that ships to the 光猫 eats the *compressed* size, so that is the number that
decides whether a driver is affordable — raw size is a red herring (a compiler
upgrade once shrank the raw binary 21% while growing the xz by 4.8%).
"""
import lzma
import sys
from pathlib import Path


def report(path: str, label: str = "") -> None:
    data = Path(path).read_bytes()
    xz = lzma.compress(data, format=lzma.FORMAT_XZ, preset=6)
    name = label or Path(path).name
    print(f"{name:<34} raw {len(data):>10,}   xz-6 {len(xz):>9,}   "
          f"({100 * len(xz) / len(data):.1f}% of raw)")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        raise SystemExit(2)
    for a in args:
        if "=" in a:
            label, _, path = a.partition("=")
            report(path, label)
        else:
            report(a)
