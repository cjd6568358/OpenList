"""End-to-end all-operation test for the GO OpenList instances
(10.0.0.4:5244 minimal build / 192.168.1.1:15244 sqfs build).

Derived from tools/e2e_test.py (the Zig-instance harness), adapted because the
Go upstream takes the JWT **bare** in Authorization (no "Bearer " prefix --
see server/middlewares/auth.go: c.GetHeader("Authorization") is compared
against the API token verbatim and fed to ParseToken as-is).

Coverage: list / get / download / Range / WebDAV read / mkdir / upload /
rename / move / remove / WebDAV PUT / MKCOL / cleanup.

Usage:
    python .temp/go_e2e.py http://192.168.1.1:15244 [--write-cloud] [--mounts a,b]
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

PASS, FAIL, SKIP = [], [], []

U, P = "e2eadmin", "e2e-test-123456"


def req(base, path, *, method="GET", token=None, body=None, headers=None, raw=False, timeout=120):
    url = base + path
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    if token:
        # Go upstream: JWT goes in BARE (no Bearer prefix)
        hdrs["Authorization"] = token
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                payload = resp.read()
                return resp.status, (payload if raw else payload.decode(errors="replace")), dict(resp.headers)
        except urllib.error.HTTPError as e:
            payload = e.read()
            return e.code, (payload if raw else payload.decode(errors="replace")), dict(e.headers)
        except (ConnectionError, TimeoutError, OSError):
            if attempt == 2:
                raise
            time.sleep(1.0)


def put_raw(base, path, data, headers):
    import http.client
    import urllib.parse
    u = urllib.parse.urlparse(base)
    for attempt in (1, 2):
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=300)
        try:
            conn.request("PUT", path, body=data, headers=headers)
            r = conn.getresponse()
            r.read()
            return r.status
        except (ConnectionError, TimeoutError, OSError):
            if attempt == 2:
                raise
            time.sleep(1.0)
        finally:
            conn.close()


def check(name, ok, detail=""):
    if ok:
        PASS.append(name)
        print("  [OK]   %-46s %s" % (name, detail))
    else:
        FAIL.append(name)
        print("  [FAIL] %-46s %s" % (name, detail))


def api(base, path, token, body=None, method="POST"):
    st, txt, _ = req(base, path, method=method, token=token, body=body)
    try:
        j = json.loads(txt)
    except Exception:
        return st, {"code": st, "_raw": txt[:200]}
    if not isinstance(j, dict):
        return st, {"code": st, "_raw_shape": repr(j)[:120], "_raw": txt[:200]}
    return st, j


def ls(base, token, path):
    st, j = api(base, "/api/fs/list", token, {"path": path, "page": 1, "per_page": 100})
    return (j.get("data", {}) or {}).get("content", []) if j.get("code") == 200 else None


def ls_eventually(base, token, path, pred, tries=12, delay=1.5):
    last = []
    for _ in range(tries):
        last = ls(base, token, path) or []
        if pred(last):
            return last
        time.sleep(delay)
    return last


def op_retry(base, token, path, body, tries=4, delay=2.0):
    last = {}
    for _ in range(tries):
        st, j = api(base, path, token, body)
        last = j
        if j.get("code") == 200:
            return j
        if "not found" not in str(j.get("message", "")):
            return j
        time.sleep(delay)
    return last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--write-cloud", action="store_true")
    ap.add_argument("--mounts", default="")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print("=== 0. login ===")
    st, txt, _ = req(base, "/api/auth/login", method="POST", body={"username": U, "password": P})
    tok = (json.loads(txt).get("data") or {}).get("token")
    check("login token", bool(tok))
    if not tok:
        return 1

    print("\n=== 1. list mounts ===")
    st, j = api(base, "/api/fs/list", tok, {"path": "/"})
    mounts = [o["name"] for o in (j.get("data", {}) or {}).get("content", [])] if j.get("code") == 200 else []
    check("virtual root lists mounts", len(mounts) > 0, "mounts: " + ", ".join(mounts))
    only = {x for x in args.mounts.split(",") if x.strip()}
    for m in mounts:
        if only and m not in only:
            continue
        c = ls(base, tok, "/" + m)
        check("list /%s" % m, c is not None, ("%d items" % len(c)) if c is not None else "fail")

    print("\n=== 2. get / download / range ===")
    target = None
    for m in mounts:
        if only and m not in only:
            continue
        for o in (ls(base, tok, "/" + m) or []):
            if not o["is_dir"] and o["size"] > 0:
                target = "/%s/%s" % (m, o["name"])
                break
        if target:
            break
    if target:
        st, j = api(base, "/api/fs/get", tok, {"path": target})
        d = j.get("data", {}) or {}
        check("fs/get %s" % target, j.get("code") == 200, "size=%s type=%s" % (d.get("size"), d.get("type")))
        check("fs/get raw_url", bool(d.get("raw_url")), str(d.get("raw_url"))[:60])
        # Go upstream: /d/*path is guarded by signCheck (sign_all=true in this
        # deployment), NOT by the Authorization header. fs/get returns the sign.
        sgn = d.get("sign", "")
        dl = "/d%s?sign=%s" % (target, sgn)
        st, body, hdrs = req(base, dl, raw=True)
        check("download /d%s" % target, st == 200 and len(body) > 0, "HTTP %d, %d bytes" % (st, len(body)))
        st, body2, _ = req(base, dl, headers={"Range": "bytes=0-3"}, raw=True)
        check("range 206", st == 206, "HTTP %d, %d bytes" % (st, len(body2)))
    else:
        check("downloadable file found", False, "no non-empty file in any mount")

    print("\n=== 3. WebDAV read ===")
    cred = base64.b64encode(("%s:%s" % (U, P)).encode()).decode()
    h = {"Authorization": "Basic " + cred, "Depth": "1"}
    st, txt, _ = req(base, "/dav/", method="PROPFIND", headers=h)
    check("PROPFIND /dav/", st == 207, "HTTP %d" % st)
    if target:
        st, txt, _ = req(base, "/dav" + target, method="PROPFIND", headers={"Authorization": "Basic " + cred, "Depth": "0"})
        check("PROPFIND %s" % target, st == 207, "HTTP %d" % st)
        st, body, _ = req(base, "/dav" + target, headers={"Authorization": "Basic " + cred}, raw=True)
        check("WebDAV GET", st == 200 and len(body) > 0, "HTTP %d, %d bytes" % (st, len(body)))

    print("\n=== 4. write ops ===")
    writable = []
    if args.write_cloud:
        writable = [m for m in mounts if (not only or m in only)]
    if not writable:
        print("  (write tests skipped: no --write-cloud)")
    for m in writable:
        tag = "goz-e2e-%d" % int(time.time())
        d = "/%s/%s" % (m, tag)
        print("  -- mount /%s (temp %s)" % (m, tag))
        st, j = api(base, "/api/fs/mkdir", tok, {"path": d})
        check("mkdir", j.get("code") == 200, str(j.get("message", "")))
        if j.get("code") != 200:
            continue
        content = b"go-e2e payload\n"
        st = put_raw(base, "/api/fs/put", content,
                     {"Authorization": tok, "File-Path": d + "/a.txt"})
        check("upload a.txt", st == 200, "HTTP %d" % st)

        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "a.txt" for x in c))
        check("a.txt visible after upload", any(x["name"] == "a.txt" for x in c), "%d items" % len(c))

        j = op_retry(base, tok, "/api/fs/rename", {"path": d + "/a.txt", "name": "b.txt"})
        check("rename a.txt -> b.txt", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "b.txt" for x in c))
        check("rename visible", any(x["name"] == "b.txt" for x in c))

        st, j = api(base, "/api/fs/mkdir", tok, {"path": d + "/sub"})
        j = op_retry(base, tok, "/api/fs/move",
                     {"src_dir": d, "dst_dir": d + "/sub", "names": ["b.txt"]})
        check("move to sub/", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d + "/sub", lambda c: any(x["name"] == "b.txt" for x in c))
        check("move visible", any(x["name"] == "b.txt" for x in c))

        j = op_retry(base, tok, "/api/fs/remove", {"dir": d + "/sub", "names": ["b.txt"]})
        check("remove file", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d + "/sub", lambda c: not any(x["name"] == "b.txt" for x in c))
        check("remove visible", not any(x["name"] == "b.txt" for x in c))

        st = put_raw(base, "/dav" + d + "/w.txt", b"webdav payload",
                     {"Authorization": "Basic " + cred})
        check("WebDAV PUT", st in (200, 201, 204), "HTTP %d" % st)
        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "w.txt" for x in c))
        check("WebDAV PUT visible", any(x["name"] == "w.txt" for x in c))

        st, txt, _ = req(base, "/dav" + d + "/sub/", method="MKCOL", headers={"Authorization": "Basic " + cred})
        check("WebDAV MKCOL", st in (201, 405), "HTTP %d" % st)

        for n in ["w.txt"]:
            api(base, "/api/fs/remove", tok, {"dir": d, "names": [n]})
        api(base, "/api/fs/remove", tok, {"dir": d + "/sub", "names": []})
        st, j = api(base, "/api/fs/remove", tok, {"dir": "/" + m, "names": [tag]})
        if j.get("code") == 200:
            check("cleanup temp dir %s" % tag, True)
        elif m == "jianguo":
            SKIP.append("cleanup %s (jianguo root-level delete 403, manual web cleanup)" % tag)
            print("  [SKIP] cleanup %s (%s)" % (tag, j.get("message", "")))
        else:
            check("cleanup temp dir %s" % tag, False, str(j.get("message", "")))

    print("\n=== summary ===")
    print("pass %d, fail %d, skip %d" % (len(PASS), len(FAIL), len(SKIP)))
    for f in FAIL:
        print("  [FAIL] " + f)
    for s in SKIP:
        print("  [SKIP] " + s)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
