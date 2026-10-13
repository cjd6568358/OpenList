"""端到端全操作测试：对着真机上跑着的 openlist-zig 打真实的 HTTP 请求。

覆盖：列目录 / 详情 / 下载 / Range / 新建目录 / 上传 / 重命名 / 移动 / 删除 /
      WebDAV(PROPFIND, GET, MKCOL, PUT, DELETE)。

**写操作默认只跑 Local 挂载点** —— 云盘上写东西会污染用户账号。
要测云盘写操作，显式加 `--write-cloud`，脚本会在一个明确命名的临时目录里做，
并在结束时清理。

用法：
    python tools/e2e_test.py http://192.168.1.1:15344 [--write-cloud]

退出码 0 = 全部通过；非 0 = 有失败项（明细打在 stdout）。
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

PASS, FAIL, SKIP = [], [], []


def req(base, path, *, method="GET", token=None, body=None, headers=None, raw=False, timeout=90):
    url = base + path
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    if token:
        hdrs["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    # 连接被重置（服务端重启/切宿主时偶发）时重试一次，别让整个矩阵崩掉。
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
    """发一个带原始 body 的 PUT（上传用）。返回状态码。"""
    import http.client
    import urllib.parse
    u = urllib.parse.urlparse(base)
    for attempt in (1, 2):
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=180)
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
        print("  ✅ %-46s %s" % (name, detail))
    else:
        FAIL.append(name)
        print("  ❌ %-46s %s" % (name, detail))


def api(base, path, token, body=None, method="POST"):
    """调一个 JSON 接口，返回 (status, dict)。

    Go 的 API 一律返回 `{"code":..,"message":..,"data":..}` 信封。如果服务端
    返回了别的形状（裸 null、非 JSON），这里归一成 `{"code": <status>}` 并保留
    原文，免得脚本自己崩掉、把「服务端不符合 Go」误报成「脚本出错」。
    """
    st, txt, _ = req(base, path, method=method, token=token, body=body)
    try:
        j = json.loads(txt)
    except Exception:
        return st, {"code": st, "_raw": txt[:200]}
    if not isinstance(j, dict):
        # 裸 `null` 之类 —— 记下原始形状，方便断言失败时一眼看出原因
        return st, {"code": st, "_raw_shape": repr(j)[:120], "_raw": txt[:200]}
    return st, j


def ls(base, token, path):
    st, j = api(base, "/api/fs/list", token, {"path": path, "page": 1, "per_page": 100})
    return (j.get("data", {}) or {}).get("content", []) if j.get("code") == 200 else None


def ls_eventually(base, token, path, pred, tries=12, delay=1.5):
    """写操作后轮询列表，直到 pred 满足或超时。

    189 个人云的 listFiles 实测有数秒延迟：rename 返回成功后立刻 list 仍是旧
    名字（家庭云同一时刻就是新的）—— Go 驱动读同一个上游 API，行为相同。
    所以「重命名生效」这类检查必须轮询，不能一锤定音。
    """
    last = []
    for _ in range(tries):
        last = ls(base, token, path) or []
        if pred(last):
            return last
        time.sleep(delay)
    return last


def op_retry(base, token, path, body, tries=4, delay=2.0):
    """对 "not found" 重试的写操作调用。

    189 的 listFiles 有秒级最终一致性延迟：刚 mkdir/上传/重命名的路径立刻去
    解析可能NotFound。Go 的前端/API 移动的是「已带 id 的对象」（从列表里来），
    天然回避这个窗口；我们这层收到的是路径、必须重新解析，所以重试。
    真失败只会晚几秒暴露，不会被掩盖。
    """
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
    ap.add_argument("--mounts", default="", help="逗号分隔，只测这些挂载点")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print("=== 0. 准备：注册/登录 ===")
    u, p = "e2eadmin", "e2e-test-123456"
    req(base, "/api/auth/register", method="POST", body={"username": u, "password": p})
    st, txt, _ = req(base, "/api/auth/login", method="POST", body={"username": u, "password": p})
    tok = (json.loads(txt).get("data") or {}).get("token")
    check("登录拿到 token", bool(tok))
    if not tok:
        return 1

    # ---- 1. 列目录（所有挂载点）----
    print("\n=== 1. 列目录 ===")
    st, j = api(base, "/api/fs/list", tok, {"path": "/"})
    mounts = [o["name"] for o in (j.get("data", {}) or {}).get("content", [])] if j.get("code") == 200 else []
    check("虚拟根列出挂载点", len(mounts) > 0, "挂载: " + ", ".join(mounts))
    only = {x for x in args.mounts.split(",") if x.strip()}
    for m in mounts:
        if only and m not in only:
            continue
        c = ls(base, tok, "/" + m)
        check("list /%s" % m, c is not None, ("%d 条" % len(c)) if c is not None else "失败")

    # ---- 2. 详情 + 下载 + Range（挑一个真实文件）----
    print("\n=== 2. 详情 / 下载 / Range ===")
    target = None
    for m in mounts:
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
        check("fs/get 带 raw_url", bool(d.get("raw_url")), str(d.get("raw_url"))[:60])
        # 下载走 sign：`sign_all=true` 的部署（用户光猫上的真实配置）里 `/d/`
        # 只认 `?sign=`，带 token 也会 401 —— 与 Go 的 Down 中间件同形。
        # sign 从 `fs/get` 响应的 `sign` 字段来；为空说明服务端没开签名，
        # 那就回落 token。
        sign = d.get("sign") or ""
        dl = "/d" + target + ("?sign=" + sign if sign else "")
        st, body, hdrs = req(base, dl, token=None if sign else tok, raw=True)
        check("下载 /d%s" % target, st == 200 and len(body) > 0,
              "HTTP %d, %d 字节%s" % (st, len(body), " (sign)" if sign else " (token)"))
        dl_r = dl + ("&" if "?" in dl else "?") + "_=0"
        st, body2, _ = req(base, dl, token=None if sign else tok,
                           headers={"Range": "bytes=0-3"}, raw=True)
        check("Range 206", st == 206, "HTTP %d, %d 字节" % (st, len(body2)))
        if sign:
            # 签名必须绑定路径：拿别处的 sign 来下应当被拒。
            bad = sign[:-1] + ("x" if sign[-1] != "x" else "y")
            st_bad, _, _ = req(base, "/d" + target + "?sign=" + bad, raw=True)
            check("篡改的 sign 被拒", st_bad == 401, "HTTP %d" % st_bad)
    else:
        check("找到可下载的文件", False, "所有挂载点都没有非空文件")

    # ---- 3. WebDAV（读）----
    print("\n=== 3. WebDAV 读 ===")
    cred = base64.b64encode(("%s:%s" % (u, p)).encode()).decode()
    h = {"Authorization": "Basic " + cred, "Depth": "1"}
    st, txt, _ = req(base, "/dav/", method="PROPFIND", headers=h)
    check("PROPFIND /dav/", st == 207, "HTTP %d" % st)
    if target:
        st, txt, _ = req(base, "/dav" + target, method="PROPFIND", headers={"Authorization": "Basic " + cred, "Depth": "0"})
        check("PROPFIND %s" % target, st == 207, "HTTP %d" % st)
        st, body, _ = req(base, "/dav" + target, headers={"Authorization": "Basic " + cred}, raw=True)
        check("WebDAV GET", st == 200 and len(body) > 0, "HTTP %d, %d 字节" % (st, len(body)))

    # ---- 4. 写操作（Local 全测；云盘需 --write-cloud）----
    print("\n=== 4. 写操作 ===")
    writable = [m for m in mounts if m == "hikvision"]
    if args.write_cloud:
        writable = [m for m in mounts if m != "hikvision"] + writable
    # `--mounts` 必须同时约束写操作：否则只想测 itvsh/aliyun 时，会把没有写
    # 权限的挂载点（例如 189pc 的家庭云目录）也一起跑了，噪声淹掉真正的失败。
    if only:
        writable = [m for m in writable if m in only]
    if not writable:
        check("存在可写挂载点", False, "没找到 hikvision")
    for m in writable:
        tag = "olz-e2e-%d" % int(time.time())
        d = "/%s/%s" % (m, tag)
        print("  -- 挂载点 /%s（临时目录 %s）" % (m, tag))
        st, j = api(base, "/api/fs/mkdir", tok, {"path": d})
        check("mkdir", j.get("code") == 200, str(j.get("message", "")))
        if j.get("code") != 200:
            continue
        # 上传：/api/fs/put 收的是**原始 body**（不是 JSON），所以用 http.client
        # 而不是上面的 JSON 包装。File-Path 头指定目标路径。
        content = b"openlist-zig e2e payload\n"
        st = put_raw(base, "/api/fs/put", content,
                     {"Authorization": "Bearer " + tok, "File-Path": d + "/a.txt"})
        check("上传 a.txt", st == 200, "HTTP %d" % st)

        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "a.txt" for x in c))
        check("上传后能看到 a.txt", any(x["name"] == "a.txt" for x in c), "%d 条" % len(c))

        j = op_retry(base, tok, "/api/fs/rename", {"path": d + "/a.txt", "name": "b.txt"})
        check("重命名 a.txt -> b.txt", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "b.txt" for x in c))
        check("重命名生效", any(x["name"] == "b.txt" for x in c))

        st, j = api(base, "/api/fs/mkdir", tok, {"path": d + "/sub"})
        j = op_retry(base, tok, "/api/fs/move",
                     {"src_dir": d, "dst_dir": d + "/sub", "names": ["b.txt"]})
        check("移动到 sub/", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d + "/sub", lambda c: any(x["name"] == "b.txt" for x in c))
        check("移动生效", any(x["name"] == "b.txt" for x in c))

        # b.txt 已经被移到 sub/ 了，要从 sub/ 删（这里原来写错了目录）
        j = op_retry(base, tok, "/api/fs/remove", {"dir": d + "/sub", "names": ["b.txt"]})
        check("删除文件", j.get("code") == 200, str(j.get("message", "")))
        c = ls_eventually(base, tok, d + "/sub", lambda c: not any(x["name"] == "b.txt" for x in c))
        check("删除生效", not any(x["name"] == "b.txt" for x in c))

        # WebDAV 写（同样是原始 body）
        st = put_raw(base, "/dav" + d + "/w.txt", b"webdav payload",
                     {"Authorization": "Basic " + cred})
        check("WebDAV PUT", st in (200, 201, 204), "HTTP %d" % st)
        c = ls_eventually(base, tok, d, lambda c: any(x["name"] == "w.txt" for x in c))
        check("WebDAV PUT 生效", any(x["name"] == "w.txt" for x in c))

        st, txt, _ = req(base, "/dav" + d + "/sub/", method="MKCOL", headers={"Authorization": "Basic " + cred})
        check("WebDAV MKCOL", st in (201, 405), "HTTP %d" % st)

        # 清理：只删自己建的临时目录
        for n in ["w.txt"]:
            api(base, "/api/fs/remove", tok, {"dir": d, "names": [n]})
        api(base, "/api/fs/remove", tok, {"dir": d + "/sub", "names": []})
        st, j = api(base, "/api/fs/remove", tok, {"dir": "/" + m, "names": [tag]})
        if j.get("code") == 200:
            check("清理临时目录 %s" % tag, True)
        elif m == "jianguo":
            # 坚果云禁止通过 API 删除根级目录（实测 403 AuthFailed），服务商
            # 规则，只能去 WEB 页面手动删。不是我们的缺陷，计为跳过。
            SKIP.append("清理临时目录 %s（坚果云根级目录 403，需 WEB 手动删）" % tag)
            print("  ⚠️ 跳过 %-46s %s（坚果云根级目录禁止 API 删除，需 WEB 手动删）"
                  % ("清理临时目录 %s" % tag, j.get("message", "")))
        else:
            check("清理临时目录 %s" % tag, False, str(j.get("message", "")))

    print("\n=== 汇总 ===")
    print("通过 %d，失败 %d，跳过 %d" % (len(PASS), len(FAIL), len(SKIP)))
    for f in FAIL:
        print("  ❌ " + f)
    for s in SKIP:
        print("  ⚠️ " + s)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
