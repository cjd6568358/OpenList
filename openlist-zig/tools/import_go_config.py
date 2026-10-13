"""Convert a Go OpenList backup/config JSON into a Zig `config.json`.

The two formats are NOT interchangeable (audit item C03): Go keeps storages in
SQLite and dumps them as `{"storages": [...]}` with the driver's *display name*
in `Storage.driver`, while the Zig build reads a top-level `storages` array from
`config.json`. Driver names must therefore be mapped, and unsupported drivers
must be dropped rather than silently mistranslated into a different driver.

Usage:
    python tools/import_go_config.py <go_backup.json> <out_config.json>
        [--port 15244] [--temp-dir /tmp/olz/temp] [--only id,id,...]

The output contains real credentials. Write it to a scratch location, never
over an existing Go config or database.
"""
import argparse
import io
import json
import os
import sys

# Zig factory keys == Go `driver.Config.Name`, verified against the Go sources.
#
# T3（2026-10-12 完成）：6 个已注册驱动的 `Addition.parse` 字段名已与 Go json tag
# 逐一对齐，且每个驱动都有「真实 Go addition JSON → 驱动」回归测试（键集取自
# openlist_backup_2026_10_11_21_41_15.json）。`addition` JSON 因此**原样透传**
# 即可，本工具不做字段重写。
#
# T2（2026-10-12 完成）：补课的三个驱动 `123Pan`(drivers/123)、`Quark`
# (drivers/quark_uc)、`115 Cloud`(drivers/115) 已实现并注册，从 UNSUPPORTED
# 移到 SUPPORTED。注意它们与 `_open` 变体是**不同驱动**，不要互相映射。
SUPPORTED = {
    "Local": "Local",
    "WebDav": "WebDav",
    "上海电信智家硬盘": "上海电信智家硬盘",
    "AliyundriveOpen": "AliyundriveOpen",
    "189Cloud": "189Cloud",
    "189CloudPC": "189CloudPC",
    # T2 补课（用户配置 + build_sqfs.yml 默认清单用的就是这三个）。
    "123Pan": "123Pan",
    "Quark": "Quark",
    "115 Cloud": "115 Cloud",
    # 下面三个是 `_open` 变体，Go 里确实存在，但**不是**默认清单与用户配置用的那个。
    # 它们的入口已在 `driver.zig` 注释掉，因此不导入。
    # "123 Open": "123 Open",
    # "QuarkOpen": "QuarkOpen",
    # "115 Open": "115 Open",
}

# 本构建不服务的驱动，附原因。T2/T3 之后剩下的都是**范围之外**的驱动。
UNSUPPORTED = {
    "BaiduNetdisk": "不在需求范围",
    "Onedrive": "不在需求范围",
    "S3": "不在需求范围",
}


def convert(backup: dict, port: int, temp_dir: str, only: set) -> tuple[dict, list]:
    storages = []
    report = []
    for s in backup.get("storages", []):
        sid = s.get("id")
        go_driver = s.get("driver", "")
        if only and sid not in only:
            continue
        zig_key = SUPPORTED.get(go_driver)
        if zig_key is None:
            why = UNSUPPORTED.get(go_driver, "unknown driver")
            report.append((sid, go_driver, s.get("mount_path"), "SKIP", why))
            continue

        addition = s.get("addition")
        if not isinstance(addition, str):
            addition = json.dumps(addition or {})

        storages.append({
            "id": sid,
            "mount_path": s.get("mount_path") or "/",
            "order": s.get("order", 0),
            "driver": zig_key,
            "cache_expiration": s.get("cache_expiration", 0),
            "status": s.get("status", "work"),
            # Kept as a JSON *string*, exactly as Go stores it and as the Zig
            # parser expects (`parseStorages` reads `addition` via `str()`).
            "addition": addition,
            "remark": s.get("remark", ""),
            "disabled": bool(s.get("disabled", False)),
        })
        report.append((sid, go_driver, s.get("mount_path"), "OK", zig_key))

    cfg = {
        "force": False,
        "site_url": "",
        "cdn": "",
        "dist_dir": "",
        "jwt_secret": "",
        "token_expires_in": 48,
        "scheme": {
            "address": "0.0.0.0",
            "http_port": port,
            "https_port": -1,
            "force_https": False,
            "cert_file": "",
            "key_file": "",
        },
        "temp_dir": temp_dir,
        "log": {"enable": True, "name": os.path.join(os.path.dirname(temp_dir), "log/log.log")},
        "max_connections": 0,
        "max_concurrency": 64,
        "tls_insecure_skip_verify": False,
        "zig": {"web_version": "rolling"},
        "storages": storages,
    }
    return cfg, report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--port", type=int, default=15244)
    ap.add_argument("--temp-dir", default="/tmp/olz/temp")
    ap.add_argument("--only", default="", help="comma separated storage ids")
    args = ap.parse_args()

    only = {int(x) for x in args.only.split(",") if x.strip()} if args.only else set()

    backup = json.load(io.open(args.src, encoding="utf-8"))
    cfg, report = convert(backup, args.port, args.temp_dir, only)

    with io.open(args.dst, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    print(f"wrote {args.dst}: {len(cfg['storages'])} storages, port {args.port}")
    print(f"{'id':>4}  {'go driver':<22} {'mount':<20} {'':<5} zig")
    for sid, go_driver, mount, verdict, extra in report:
        print(f"{sid:>4}  {go_driver:<22} {mount or '':<20} {verdict:<5} {extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
