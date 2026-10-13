#!/usr/bin/env python3
"""逐驱动体积分解。

做法：把 `src/driver.zig` 的 `builtin` 表里的某一行注释掉，重新交叉编译，
用「全集 − 去掉该项」的差作为该驱动的边际体积。裸体积和 xz 后体积都记 ——
squashfs 吃的是压缩后的体积，所以 xz 那一列才是真正要关心的。

用法：
    python tools/driver_size.py            # 全量（基线 + 每个驱动各一次）
    python tools/driver_size.py --only 189 # 只测某一项
"""

import lzma
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER_ZIG = os.path.join(ROOT, "src", "driver.zig")
OUT = os.path.join(ROOT, "dist", "openlist-aarch64")
# Temporary full-build snapshot used to restore OUT after each exclusion run.
# Keep it separate from the checked-in historical .baseline / .prev artifacts.
CACHE_BIN = os.path.join(ROOT, "dist", "openlist-aarch64.driver-size-base")

ZIG = os.environ.get(
    "ZIG",
    r"C:/Users/Administrator/.workbuddy-ai/binaries/zig/0.17.0/zig-x86_64-windows-0.17.0/zig.exe",
)
ENV = dict(os.environ)
ENV["ZIG_GLOBAL_CACHE_DIR"] = "C:/Users/Administrator/AppData/Local/Temp/z17gcache"

TARGET = ["-target", "aarch64-linux-musl", "-O", "small", "-lc", "-fstrip"]


def read_drivers():
    """返回 (注册表的原始文本块, [(名字, 该行文本)])。"""
    src = open(DRIVER_ZIG, encoding="utf-8").read()
    m = re.search(r"pub const builtin = \[_\]Factory\{(.*?)\n\};", src, re.S)
    if not m:
        sys.exit("找不到 builtin 表")
    block = m.group(1)
    rows = []
    for line in block.split("\n"):
        s = line.strip()
        if not s.startswith("@import("):
            continue
        mm = re.match(r'@import\("drivers/(.+?)\.zig"\)\.factory,', s)
        if mm:
            rows.append((mm.group(1), s))
    return block, rows


def build(out):
    cmd = [ZIG, "build-exe", "src/main.zig", "--name", "openlist",
           *TARGET, "-femit-bin=" + out]
    r = subprocess.run(cmd, cwd=ROOT, env=ENV,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0:
        sys.stdout.write(r.stdout.decode("utf-8", "replace"))
        sys.exit("编译失败")
    return os.path.getsize(out)


def xz_size(path):
    raw = open(path, "rb").read()
    return len(lzma.compress(raw, format=lzma.FORMAT_XZ, preset=6))


def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]

    block, rows = read_drivers()
    src_orig = open(DRIVER_ZIG, encoding="utf-8").read()
    print(f"注册表里 {len(rows)} 个驱动：{', '.join(n for n, _ in rows)}")

    t0 = time.time()
    base_raw = build(OUT)
    shutil.copyfile(OUT, CACHE_BIN)
    base_xz = xz_size(OUT)
    print(f"\n基线（全量）          raw {base_raw:>9,}  xz {base_xz:>9,}   ({time.time()-t0:.0f}s)\n")

    results = []
    for name, line in rows:
        if only and only != name:
            continue
        # 注释掉这一行
        patched = src_orig.replace(line, "// " + line, 1)
        assert patched != src_orig
        open(DRIVER_ZIG, "w", encoding="utf-8", newline="").write(patched)
        try:
            t = time.time()
            raw = build(OUT)
            xz = xz_size(OUT)
        finally:
            open(DRIVER_ZIG, "w", encoding="utf-8", newline="").write(src_orig)
        results.append((name, base_raw - raw, base_xz - xz, raw, xz, time.time() - t))
        print(f"  - {name:<16} raw {raw:>9,} (Δ{base_raw-raw:>+8,})  "
              f"xz {xz:>9,} (Δ{base_xz-xz:>+8,})   ({time.time()-t:.0f}s)")

    # 恢复基线产物并清理临时快照；历史 baseline / prev 不会被覆盖。
    shutil.copyfile(CACHE_BIN, OUT)
    os.remove(CACHE_BIN)

    print("\n边际体积（从大到小，按压缩后排序）")
    print(f"{'驱动':<18}{'Δraw':>10}{'Δxz':>10}{'xz 占比':>10}")
    for name, d_raw, d_xz, _, _, _ in sorted(results, key=lambda r: -r[2]):
        print(f"{name:<18}{d_raw:>10,}{d_xz:>10,}{d_xz/base_xz*100:>9.1f}%")
    print(f"{'合计（各驱动）':<16}{sum(r[1] for r in results):>10,}{sum(r[2] for r in results):>10,}")


if __name__ == "__main__":
    main()
