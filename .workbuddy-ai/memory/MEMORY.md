# openlist-zig —— 项目长期记忆

## 项目目标与驱动状态

**最终目标（用户 2026-10-10）**：基于 `build_sqfs.yml`，用 Zig 重写完整应用，9 个驱动
全部落地并编译通过：`local`/`webdav`/`189`(个人+家庭)/`123`/`aliyun`/`quark`/`115`/`itvsh`。
**验收标准 = 9 个驱动全部写完 + 编译 + 真机验证。**

| 驱动 | Go 目录 / Name | Zig 实现 | 状态 |
|---|---|---|---|
| local | `Local` | `local.zig` | ✅ 真机验证 |
| webdav(客户端) | `WebDav` | `webdav.zig` | ✅ 真机验证（PROPFIND 207 / GET 200 逐字节） |
| itvsh 上海电信智家硬盘 | `上海电信智家硬盘` | `itvsh.zig` | ✅ 样板驱动 |
| 189 个人 | `189Cloud` | `cloud189.zig` | ✅ 真机验证 |
| 189 家庭(PC) | `189CloudPC` | `cloud189pc.zig` | ✅ 真机验证 |
| 123 | `123Pan`(用户名+密码) | `pan123.zig` | ✅ 实现完成（T2 补课变体） |
| aliyun | `AliyundriveOpen` | `aliyundrive.zig` | ✅ 真机验证 |
| quark | `Quark`(Cookie) | `quarkuc.zig` | ✅ 实现完成（T2 补课变体） |
| 115 | `115 Cloud`(Cookie) | `pan115.zig` | ✅ 实现完成（T2 补课变体） |
| **WoPan 联通沃云盘** | `WoPan`(refresh_token) | `wopan.zig` | ✅ 2026-10-13 实现+注册，**未真机**（无凭据配置） |

**T2（2026-10-12）补课**：同网盘常有两个不兼容驱动，用户配置用 `123Pan`/`Quark`/`115 Cloud`
（非 `_open` 系列）。三者已补齐并注册；`123_open`/`quark_open`/`115_open` 代码保留不注册。
**2026-10-13 加做 WoPan**（用户临时要求的额外驱动，不在 9 个清单内）。

## 关键工程约定

- **编译/测试/打包统一走打包机 10.0.0.4**（Debian 13 x86_64，root/e3eb773F）。
  只读用 `/root/.cache/` 工具链（zig 0.17.0）；源码与独立缓存放 `/root/olz-*`，
  不得改环境或装工具链。**本机产物只能自测，不能当交付。**
- **Zig 0.17.0 硬下界**。本机路径 `C:/Users/Administrator/.workbuddy-ai/binaries/zig/0.17.0/`。
- **本机 D 盘跑 `zig build` 不行**（maker.exe 无法在 D 盘建子进程）。一律用
  `zig build-exe`/`zig test` 直接调用 + 独立 `ZIG_GLOBAL_CACHE_DIR` + 非沙箱执行。
- **每个驱动都要有单元测试**（`std.testing.allocator` 抓泄漏）。提交前 `zig test` 和
  交叉编译都要过（`tools/build_remote.py` 走打包机，目标 `aarch64-linux-musl`，加 `-lc -fstrip`）。
- **D 盘满 → 测试假报 NoSpaceLeft/泄漏**：先看磁盘。清理大头是 `openlist-zig/.zig-cache`
  （构建缓存）。删大目录用 `cmd //c "rd /s /q"`，别用 Git Bash `rm -rf`。
- **驱动名铁律**：`factory.key` 必须逐字节等于 Go 的 `driver.Config.Name`
  （即写进 `Storage.driver` 的字符串）。历史名只能进 `Factory.aliases`。
- **上游唯一事实来源 = 本地 `D:\workspace\OpenList` 树**（`drivers/<name>/`）。
  不要去 GitHub 拉；`itvsh` 是用户私有驱动，只存在于本地树。
- **SFTP 驱动（2026-10-11 拍板 defer）**：存档 `docs/FEASIBILITY.md` §5.3，非本轮目标。

## 真机部署（光猫 192.168.1.1:10022，隔离目录 `/tmp/olz`）

- **大二进制必须用 SCP 传**（WinSCP SCP 协议，或 paramiko `scp -t` 模式）。SFTP 传
  1.1MB 必断（EOFError）；10KB 配置正常。端口 15344（先 `netstat -ltn` 选空闲）。
- 设备 busybox 阉割：`chmod` 完全失效（用 SFTP `sftp.chmod()`）；无 `pkill`/`stat`；
  ash 不支持 `for..do`；`umask` 恒 0；`base64` 不在 PATH。
- **只留一个进程**：SO_REUSEPORT 下多进程同监听同端口会被随机分发，造出
  「register 成功但 login 报 no administrator yet」假 bug。杀用 `kill -9`（SIGTERM 无效），
  杀完 `ps`+`netstat` 双确认。
- Zig 版显示前端须配 **线上 CDN**（`cdn`+`web_version=rolling`，`dist_dir` 留空）：
  `https://cdn.jsdelivr.net/npm/@openlist-frontend/openlist-frontend@latest/dist`。
- 配置转换 `tools/import_go_config.py <go备份> <out.json>`；测完清理 `/tmp/olz` + 自进程，
  **绝不动 `/opt/sq/openlist` 与 Go 的 config.json/data.db**。

## 下载签名 sign（2026-10-13）

- 算法逐字对齐 Go `pkg/sign/hmac.go`：带 padding 的 URL-safe base64(HMAC-SHA256) + `:expire`，
  `expire=0` 永不过期，secret 用 `jwt_secret`。config 新增 `sign_all`/`link_expiration`。
- **⚠️ `/d/`、`/p/` 必须是独立于 `handleAuthed` 的路由**（对齐 Go 的 Down 中间件）。曾因挂在
  `handleAuthed` 下被开头 `checkAuth` 拦掉，sign 下载恒 401 —— 已修，并加路由级回归测试
  （`/d/` 带合法 sign 无 token 必须放行；无 sign 无 token → 401）。

## 移植踩坑（复用）

- **189 列表项 `id` 是 JSON 数字**：缺 id 报 `InvalidResponse`，不静默返空串（否则
  rename/move/delete 被拒、mkdir 落根目录静默错位）。
- **189 个人云 list 有秒级最终一致性延迟**（家庭云无）→ 不是 bug，e2e 轮询容忍。
- **Zig 0.17 std.http 坑**：① TLS 下 `BodyWriter.end()` 不 flush 底层 stream，需补
  `connection.flush()`；② `redirect_behavior=.not_allowed` 遇 3xx 直接报错，跟跳须 `.unhandled`；
  坚果云 DELETE 204 无定界头 → `Request.skip_body` 别读正文。
- **itvsh/123/quark 上游 `Copy` 就是 `NotSupport`** —— 这三个驱动**故意不实现 copy**
  （vtable `.copy=null`），有显式测试钉住「别顺手补上」。
- **`driver.ProgressFn` 是 0–100 百分比**（Go `model.UpdateProgress`），勿传字节数。
- **WoPan 协议**：单一 `dispatcher` 入口（POST `panservice.mail.wo.cn/{channel}/dispatcher`，
  channel∈api-user/wohome）；header 签名 = `md5(key+resTime毫秒+reqSeq+channel)` 小写 hex；
  body 的 `param` = AES-128-CBC+PKCS7（IV=`wNSOYIB1k1DjY5lA`，key：api-user 用 clientSecret
  `XFmi9GS2hzk98jGX`，wohome 用 accessToken 前 16 字节）后 base64；响应 `RSP.DATA` 若是
  `"..."` 包裹的密文则同样解密。上传走 `{zoneURL}/openapi/client/upload2C` 的 multipart。

## 验证历史（压缩）

- 2026-10-12：242/242 单测 + 真机六存储挂载；e2e 106 通过/1 跳过（坚果云根级删除）。
- 2026-10-13 晚（sign 路由修复 + WoPan 实现）：本机 328 通过/3 跳过/0 失败；打包机 **331 全过**；
  aarch64 二进制 1,144,608 B；光猫 `/api/admin/driver/names` 含 `WoPan`（共 10 驱动）。
- **2026-10-13 深夜（终态）**：Zig↔Go 重新核对 7 个在用驱动（全部 faithful，189pc 签名逐字节一致），
  修 Local move 子树防护 + Quark makeDir 冲突语义；交叉编译 1,144,432 B；光猫用真实配置重跑 e2e
  **32 通过 / 0 失败 / 0 跳过**。
- 最新结论统一收敛到 `openlist-zig/docs/STATUS.md`（旧审计报告 GO_ZIG_AUDIT/AUDIT_VERIFY/
  DRIVER_COMPARE/CHECKLIST/T2_COMPLETE/TODO 已删除）。

## 项目未来放置（2026-10-13 用户计划）

- `openlist-zig` 后续会放进 `D:\workspace\OpenList` 作为**子目录**，紧挨 Go 的 `drivers/` 树，
  方便逐文件对比上游。届时 Zig 驱动 = `openlist-zig/src/drivers/<name>.zig`，Go = `drivers/<name>/`。
- 本 `.workbuddy-ai/memory/` 当前挂在 `OpenList` 项目下；项目移动后应随 `openlist-zig` 一起搬迁到
  `OpenList/openlist-zig/.workbuddy-ai/memory/`，使其成为自包含子项目。
