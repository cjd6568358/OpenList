# openlist-zig

用 Zig 重写 OpenList 的可行性验证工程 —— 目标是把一个 OpenList 兼容的服务塞进
中兴 F4610U 光猫（aarch64 / musl / squashfs）的极小空间里。

**注册的十个驱动已全部实现（2026-10-13）。** 驱动集已于 2026-10-12 更换为
「正确变体」：`123Pan`（用户名+密码）、`Quark`（Cookie）、`115 Cloud`（Cookie）取代
原 `123 Open`/`QuarkOpen`/`115 Open`（后三者代码保留但不再注册）。
`115 Cloud` 的上传链是协议最重的部分（P-224 ECDH `ec115` + RSA/XOR `m115` + OSS），
2026-10-12 补齐；**2026-10-13 晚加做联通沃云盘 `WoPan`**（不在原 9 清单内）。
当前状态与最新结论见 [`docs/STATUS.md`](docs/STATUS.md)。
功能边界不变：
远程 Range 仍经现有 HTTP client 缓冲响应；归档暂只支持本地 ZIP/TAR 列表，不支持远程归档、解压下载、ZIP64/加密。上传进度回调已全线接通（所有驱动按 Go `model.UpdateProgress` 报 0–100 百分比；itvsh 因并发上传用原子计数 + 独立轮询线程），但**尚无 `/api` 端点把它暴露给前端**。SFTP SSH 服务端**明确暂缓**（2026-10-11 决策 defer，备选 SSH 实现见 [`docs/STATUS.md`](docs/STATUS.md) §9，恢复时从该处继续）。

Zig **0.17.0** 下 **328 passed / 3 skipped** 单元测试通过（3 项 itvsh 上传用例跳过；打包机 Linux 上 331/331 全通过）；
交叉编译出的 aarch64 静态二进制为
**1,144,432 B**（Go 版全量驱动为 45,154,464 B，裸小约 39.4 倍）。
本机端到端既有冒烟覆盖登录 / 文件操作 /
12 MiB 上传下载 / 并发 / 路径穿越防护 / 前端三种加载模式 / WebDAV 服务端；真机
e2e 覆盖云盘全操作（见 [`docs/STATUS.md`](docs/STATUS.md) §3）。

当前注册的十个驱动（对应用户真实配置与需求；与 `build_sqfs.yml` 默认清单的关系
及逐驱动与上游对比见 [`docs/STATUS.md`](docs/STATUS.md) §2）：

| 驱动 | 注册名 | xz 边际 | 备注 |
|---|---|---|---|
| `189pc`（家庭云） | `189CloudPC` | 24,268 B | 最大（5.4%）。RSA + AES-CBC + HMAC 签名；move/delete 走批处理签名 |
| `pan115` | `115 Cloud` | 23,388 B | T2 新增：Cookie + `ec115` P-224 ECDH 上传链 + `m115` RSA/XOR + 闪传/OSS |
| `itvsh` | `上海电信智家硬盘` | 15,944 B | 协议最复杂：登录链 + 分块并发 |
| `aliyundrive_open` | `AliyundriveOpen` | 12,560 B | 两阶段秒传（`PreHashMatched`） |
| `pan123` | `123Pan` | 12,536 B | T2 新增：用户名+密码 + CRC32 签名 + 16 MiB 分片 |
| `189`（个人云） | `189Cloud` | 11,088 B | RSA 表单登录 + cookie 会话 |
| `quarkuc` | `Quark` | 9,900 B | T2 新增：Cookie + __puus 滚动 + OSS 分片 |
| `webdav`（客户端） | `WebDav` | 9,548 B | 含迷你 XML 解析器 |
| `local` | `Local` | 5,696 B | |
| `wopan`（联通沃云盘） | `WoPan` | — | 2026-10-13 晚新增：dispatcher + AES-128-CBC + MD5 签名；未重测边际 |

> 边际体积按 **2026-10-13 上午**（T2 三驱动补齐后、审计 P1/P2 修复前）的注册表重测
> （`dist/driver_size.log`）：全量基线 **1,071,776 B** 裸 / **450,416 B** xz，九驱动合计
> **+296,096 B** 裸 / **+124,928 B** xz，框架地板 775,680 B 裸 / 325,488 B xz。
> 当天的审计 P1/P2 修复与 P3/功能族补齐把基线进一步推到 **1,116,568 B**
> （含 digest/mime/html/copy/进度等新代码，未重测边际）；10-13 晚再加 `wopan` 后
> 最终 aarch64 二进制为 **1,144,432 B**（见 [`docs/STATUS.md`](docs/STATUS.md) §3）。
> 三个 `_open` 变体（123 Open / QuarkOpen / 115 Open）已下线未注册，
> 其历史边际（9,868 / 9,312 / 16,188 B）属 `_open` 时代的测量。

## 这个仓库里有什么

```
src/
  main.zig           入口：参数、配置、挂载、监听、信号
  rt.zig             进程级 Io 与 gpa（0.17 把 fs/net 搬进了 std.Io）
  config.zig         config.json（OpenList 兼容子集 + 写回）
  log.zig            分级日志
  model.zig          Obj / File / Link / Storage / Source
  driver.zig         驱动 vtable + 注册表 + 持久化钩子
  http.zig           手写 HTTP/1.1 服务端（std.Io.net）
  client.zig         上游 HTTP 客户端（std.http 的唯一接触面）
  frontend.zig       前端服务：CDN / dist_dir / 内置占位页三选一
  cookiejar.zig      cookie jar（Go http.Cookie 兼容持久化）
  api.zig            /api/* 路由、挂载解析、JWT 鉴权、静态资源与 SPA 兜底
  util/
    buf.zig          Buf / List（绕开 std.ArrayList 的版本漂移）
    json.zig         手写 JSON
    url.zig          URL 解析、percent 编码、query 构建
    aes.zig          AES-ECB/CBC + PKCS7 + hex
    xml.zig          WebDAV PROPFIND 用的迷你 XML 解析器
    hash.zig         MD5/SHA1/SHA256、HMAC-SHA1、base64、流式 hasher
    rsa.zig          RSA PKCS#1 v1.5 加密 + PEM/SPKI 解析（189 / 189pc 用）
    ec115.zig        115 上传口令：P-224 ECDH + EncodeToken + AES-CBC/LZ4
    m115.zig         115 下载口令：RSA-1024 裸模数 + 多层异或
    time.zig         日历算术、RFC3339 / CN 时间解析、两种固定格式输出
  drivers/
    local.zig        本地存储
    webdav.zig       WebDAV 客户端
    itvsh.zig        上海电信智家硬盘（协议最复杂的一个）
    aliyundrive.zig  阿里云盘开放平台
    cloud189.zig     天翼云盘个人版
    cloud189pc.zig   天翼云盘 PC 端 / 家庭云
    pan123.zig       123 网盘（用户名+密码版，T2 新增）
    quarkuc.zig      夸克网盘（Cookie 版，T2 新增）
    pan115.zig       115 网盘（Cookie 版，T2 新增：ec115 P-224 ECDH + OSS 上传链）
    123open.zig      123 开放平台（已下线，代码保留）
    quark.zig        夸克开放平台（已下线，代码保留）
    115open.zig      115 开放平台（已下线，代码保留）
  tests.zig          测试聚合入口
tools/
  size.py              裸体积 + xz -6 体积
  driver_size.py       逐驱动边际体积（逐个裁掉注册表条目再编译）
  e2e_test.py          端到端全操作测试（Local 写 + 可选 --write-cloud）
  import_go_config.py  Go 备份 → Zig 配置转换
docs/
  STATUS.md          当前状态与最新结论（看这个）
```

## 构建

> **⚠️ 规则：本地需要打包 / 编译时，一律走打包编译机 `10.0.0.4`（工作目录 `/tmp`）。**
> 本地机器性能不行、磁盘空间不够，**不在本地出交付产物**。交付二进制统一用
> `tools/build_remote.py` 生成 —— 它已封装「SSH 上传源码 → 打包机 `zig test`
> → 交叉编译 `aarch64-linux-musl` → 校验 ELF 后取回」全流程。本机只负责读源码、
> 写代码和跑单元测试自测；**本机产物只能自测，不能当交付**。

**必须用 Zig 0.17.0 或更高。** 0.15 把 `std.fs`/`std.net` 搬进了 `std.Io`，
0.16 搬完，0.17 又改了入口签名（`main` 收 `std.process.Init`）和优化档位
（`std.lang.Optimize`）。本工程已完成 0.17 迁移，API 假设对应 0.17。

本机（Windows）的工具链放在：

```
C:/Users/Administrator/.workbuddy-ai/binaries/zig/0.17.0/zig-x86_64-windows-0.17.0/zig.exe
```

PyPI 的 `ziglang` 最高只到 0.16.0，**没有 0.17 的 wheel**，所以是从社区镜像
下的官方 zip（sha256 与官方一致）。镜像测速与获取过程见
[`docs/STATUS.md`](docs/STATUS.md) §5（工具链）。

```sh
Z="C:/Users/Administrator/.workbuddy-ai/binaries/zig/0.17.0/zig-x86_64-windows-0.17.0"
export ZIG_GLOBAL_CACHE_DIR="C:/Users/Administrator/AppData/Local/Temp/z17gcache"

# 单元测试
"$Z/zig.exe" test src/tests.zig

# 目标产物：aarch64 + musl + 全静态
"$Z/zig.exe" build-exe src/main.zig --name openlist \
  -target aarch64-linux-musl -O small -lc -fstrip
```

> **⚠️ 本机上 `zig build` 在 `D:` 盘跑不起来。** 它的 `maker.exe` 无法在 D 盘
> 目录里创建子进程，报 `error: spawning command Unexpected: "... configurer ..."`，
> 连最小工程都失败；同一工程复制到 C 盘则正常。这是环境限制，不是工程问题。
> 所以上面的命令用 `zig build-exe` 直接调用（不经 maker，在 D 盘完全正常）。
> 另外 `%LOCALAPPDATA%\zig` 里如果有旧版遗留的 `maker.exe` 会污染缓存，务必
> 用独立的 `ZIG_GLOBAL_CACHE_DIR`。
>
> 若在 Linux/C 盘上工作，`zig build` / `zig build test` 的等价写法见
> `build.zig`，两者是通的。

> **注意：单元测试全绿不等于能编出二进制。** Zig 按函数惰性分析，
> 测试没触发的代码路径不会实例化 —— 实测有 4 个 `std.http` 相关的错误只有
> 交叉编译才暴露。流程必须是 test → build，两个都过才算数。

首次启动会在 `data/config.json` 生成默认配置和一个随机 `jwt_secret`。
然后：

```sh
# 创建管理员（仅首次可用）
curl -s -X POST localhost:5244/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}'

# 拿 token
TOKEN=$(curl -s -X POST localhost:5244/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

curl -s -X POST localhost:5244/api/fs/list \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"path":"/"}'
```

## 前端

`/`、`/@manage/*`、`/manifest.json` 和 `/assets|images|streamer|static/*` 由
`frontend.zig` 提供，逻辑照抄 OpenList 的 `server/static/`。三种模式：

| 条件 | 行为 |
|---|---|
| `cdn` 为空、`dist_dir` 为空 | 内置占位页（本项目**不**把前端编进二进制） |
| `dist_dir` 非空 | 从该目录读 `index.html` 并服务四个资源前缀，`Cache-Control: max-age=15552000` |
| `cdn` 非空 | 启动时拉 `{cdn}/index.html`，四个资源前缀 302 到 CDN |

`cdn` 里的 `$version` 会替换成 `web_version` 去掉前导 `v`（`v4.2.6` → `4.2.6`），
这是原版 `build.sh` 把前端 release tag 喂进 CDN 模板的方式。

**推荐做法**：下载官方 lite 前端（约 2.9 MB，完整版约 20 MB）解压到
`data/dist`，然后 `"dist_dir": "data/dist"`。这样既有完整界面，二进制又不受影响。

```json
{ "dist_dir": "data/dist" }
```

## 配置

直接读 OpenList 的 `config.json`。未知字段原样保留，`storages[].addition`
仍然是 JSON **字符串**（Go 版就是这么存的），所以两种构建可以互相迁移。
Zig 特有的东西放在 `zig` 块里，Go 版会忽略它：

```json
{
  "scheme": { "address": "0.0.0.0", "http_port": 5244 },
  "site_url": "",
  "cdn": "",
  "dist_dir": "data/dist",
  "storages": [
    { "id": 1, "mount_path": "/nas", "driver": "Itvsh",
      "addition": "{\"mobile\":\"138...\",\"password\":\"...\"}",
      "status": "work" }
  ],
  "zig": {
    "ca_bundle": "data/ca.pem",
    "http_timeout": 60,
    "web_version": "rolling",
    "site_title": "OpenList (zig)",
    "main_color": "#1890ff",
    "admin_user": "admin",
    "admin_password_hash": "..."
  }
}
```

`site_url` / `cdn` / `dist_dir` 是原版的键；`web_version` 及之后的展示类设置
原版存在数据库里（本工程没有数据库），所以挪到了 `zig` 块。

## 已实现 / 未实现

**已实现**：配置加载与写回、挂载点解析（最长前缀 + 段边界）、JWT 鉴权、
`/api/fs/{list,get,dirs,mkdir,rename,move,remove,put}`、本地与代理下载（本地支持单 Range 流式，代理转发 Range）、
本地 ZIP/TAR 归档目录列表（`/api/fs/archive/list`）、驱动层上传进度 callback（目前 Local 逐块触发）、
设置接口（`/api/admin/setting/{list,get,default,save}`，仅 config-backed 项）、存储/驱动只读接口、
任务中心空的 undone/done 列表、cookie 持久化、itvsh 完整协议（登录链 / 列表 / 上传分块并发 / 可回滚收尾 / 会话自愈）、
**前端服务**（CDN / `dist_dir` / 内置占位页，含占位符替换与 PWA manifest），
**WebDAV 服务端**（`/dav`：PROPFIND/MKCOL/GET/PUT/DELETE/COPY/MOVE，Windows 资源管理器可挂载）。

**已冒烟验证**：CLI、启动加载、
注册/登录/重启后登录、目录列举、`mkdir`/`rename`/`move`/`remove`、
4 KiB 与 12 MiB 上传下载逐字节一致、12 MiB 落盘 spool 路径、20 并发、
未授权 401、路径穿越沙箱、挂载段边界（`/local2` 不匹配 `/local`）、
前端三种模式与全部路由（含 302 跟随到 CDN）。

**已真机验证**（2026-10-13 晚，`tools/e2e_test.py`，详见 [`docs/STATUS.md`](docs/STATUS.md) §3）：
用用户真实配置（10 存储）跑出 **32 通过 / 0 失败 / 0 跳过** —— 9 挂载点全部列出、
详情/下载/Range/sign 校验（含篡改 sign 被 401 拒）、WebDAV 读（PROPFIND 207 / GET 200 逐字节）、
Local 全量写操作 13 项（mkdir/上传/重命名/移动/删除/WebDAV PUT/MKCOL/清理）全过。
**十个驱动中九个已真机验证**；`WoPan` 仅注册 + 单测，因当前配置无 refresh_token 未真机。

**未实现或仅部分实现**（见 [`docs/STATUS.md`](docs/STATUS.md) §9）：
数据库与多用户体系、搜索、分享链接、后台任务/离线下载、归档解压与文件下载、远程归档浏览、
远程 Range 的真正响应流式、完整设置与存储 CRUD、任务中心操作接口。
**SFTP SSH 服务端：明确暂缓（defer）**，非本轮目标；备选 SSH 实现分析见 [`docs/STATUS.md`](docs/STATUS.md) §9。

## 已知平台差异

`std.Io.Dir.statFile` 在 **Windows 上对目录返回 `error.IsDir`**（把目录当文件打开
需要 `FILE_FLAG_BACKUP_SEMANTICS`，std 不传）。`local` 驱动因此做了回退：`statFile`
失败时用 `entry.kind`（Windows 上它是准的），`details` 用 `openDir` 探一次。
Linux 目标上不会触发，但回归测试会覆盖。

`std.posix.setsockopt` 在 Windows 上是 `@compileError`（std 要求用 `std.Io`），
所以 `http.zig` 的读写超时是 `comptime` 跳过 Windows 分支 —— 该超时只在
Linux 目标上生效。

## 许可

与 OpenList 一致。

> AI生成