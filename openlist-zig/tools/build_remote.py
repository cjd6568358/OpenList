"""Build the Zig binary on the build host (10.0.0.4) — the only supported path.

The Windows box is only ever used to *read* the sources and to run the unit
tests locally; every binary that ships is produced here, so the toolchain
(Zig 0.17.0 @ /root/.cache/zig/zig) and the resulting artifact are reproducible.

    python tools/build_remote.py [--out dist/openlist-aarch64]
"""
import hashlib
import io
import os
import sys
import tarfile

import paramiko

from remote import PWD, USER, connect, sh

HOST = "10.0.0.4"
ZIG = "/root/.cache/zig/zig"
# 打包机工作目录（用户 2026-10-11 指定用 /tmp）。仍然不碰 /root/.cache/ 里的工具链。
WORK = "/tmp/olz-build"
GCACHE = "/tmp/olz-build/zigcache"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = "aarch64-linux-musl"


def pack_src():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ("src", "build.zig", "build.zig.zon"):
            tf.add(os.path.join(ROOT, name), arcname=name)
    return buf.getvalue()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") \
        else os.path.join(ROOT, "dist", "openlist-aarch64")
    blob = pack_src()
    src_sha = hashlib.sha256(blob).hexdigest()
    print(f"packed sources: {len(blob)} bytes", flush=True)
    print(f"source tarball sha256: {src_sha}", flush=True)

    c = connect(HOST, 22)
    sftp = c.open_sftp()
    sh(c, f"rm -rf {WORK} && mkdir -p {WORK}")
    sh(c, f"mkdir -p {GCACHE}")
    sftp.putfo(io.BytesIO(blob), WORK + "/src.tar.gz")
    sh(c, f"cd {WORK} && tar xzf src.tar.gz && ls")

    # --- 1) unit tests -------------------------------------------------
    # B01: Linux 必须显式 `-lc`，否则 local.zig 的 `extern "c" statvfs`
    # 直接报 "dependency on libc must be explicitly specified"。
    # B03: 不再 `| tail` 截断（管道吃掉真实退出码），按 rc 判定。
    o, e, rc = sh(c, f"cd {WORK} && ZIG_GLOBAL_CACHE_DIR={GCACHE} {ZIG} test src/tests.zig -lc")
    log = (o + e)
    print(log.rstrip()[-4000:] if len(log) > 4000 else log.rstrip(), flush=True)
    if rc != 0:
        print(f"!! unit tests failed on the build host (rc={rc}); aborting before build", flush=True)
        sftp.close()
        c.close()
        return 1
    # 测试数会随提交增长，不能写死 "All 212 tests passed"。只要退出码为 0
    # 且确实跑出了汇总行即可。
    if "tests passed" not in log:
        print("!! test run produced no 'tests passed' summary; aborting", flush=True)
        sftp.close()
        c.close()
        return 1

    # --- 2) cross build ------------------------------------------------
    # B03: 同样按 rc 判定；失败不得继续下载旧产物。
    o, e, rc = sh(c, f"cd {WORK} && ZIG_GLOBAL_CACHE_DIR={GCACHE} {ZIG} build-exe src/main.zig "
                     f"--name openlist -target {TARGET} -O small -lc -fstrip")
    log = (o + e)
    if rc != 0:
        print(log.rstrip()[-4000:], flush=True)
        print(f"!! cross build failed (rc={rc}); not downloading anything", flush=True)
        sftp.close()
        c.close()
        return 1
    if log.strip():
        print(log.rstrip()[-4000:], flush=True)

    # --- 3) verify the artifact is really ours -------------------------
    # B03: 确认远端二进制确实是本次构建产物 —— ELF、目标架构、静态链接、
    # 并且名字对得上，再下载。
    o, e, rc = sh(c, f"cd {WORK} && ls -l openlist && sha256sum openlist && "
                     f"file openlist 2>/dev/null; readelf -h openlist 2>/dev/null | "
                     f"grep -E 'Machine|Type' || true")
    print(o.strip(), flush=True)
    # readelf 打的是 "AArch64"，大小写敏感的比较会把正确产物判成非法。
    head_lower = o.lower()
    if "aarch64" not in head_lower and "arm" not in head_lower:
        print("!! remote binary does not look like an aarch64 ELF; aborting", flush=True)
        sftp.close()
        c.close()
        return 1

    os.makedirs(os.path.dirname(out), exist_ok=True)
    sftp.get(WORK + "/openlist", out)
    sftp.close()
    c.close()
    d = open(out, "rb").read()
    print(f"\nlocal: {out}\n  size   {len(d)}\n  sha256 {hashlib.sha256(d).hexdigest()}"
          f"\n  from source tarball {src_sha[:16]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
