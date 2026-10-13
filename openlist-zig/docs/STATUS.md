# openlist-zig —— 当前状态与结论（2026-10-13）

> 本文是项目**唯一的最新结论文档**。历史审计报告（GO_ZIG_AUDIT / AUDIT_VERIFY /
> DRIVER_COMPARE / CHECKLIST / T2_COMPLETE / TODO）与早期可行性评估（FEASIBILITY.md）
> 均已删除 —— 它们承载的过时结论已汇入此处，设计/可行性背景因项目已完成而不再适用。

## 1. 目标与验收

- 用 Zig 重写 OpenList 兼容服务，塞进中兴 F4610U 光猫（aarch64 / musl / squashfs）。
- **验收标准**：驱动全部写完 + 编译 + 真机验证。
- **当前状态**：10 个驱动全部实现、注册、编译通过；单元/交叉编译全绿；真机 e2e **32 通过 / 0 失败 / 0 跳过**。

## 2. 驱动清单（10 个，全部注册）

| 驱动 | 注册名（= Go `driver.Config.Name`） | Zig 文件 | 真机验证 |
|---|---|---|---|
| local | `Local` | `local.zig` | ✅ |
| webdav（客户端） | `WebDav` | `webdav.zig` | ✅（PROPFIND 207 / GET 200 逐字节） |
| itvsh 上海电信智家硬盘 | `上海电信智家硬盘` | `itvsh.zig` | ✅ 样板驱动 |
| 189 个人云 | `189Cloud` | `cloud189.zig` | ✅ |
| 189 家庭云（PC） | `189CloudPC` | `cloud189pc.zig` | ✅ |
| 123 网盘 | `123Pan`（用户名+密码） | `pan123.zig` | ✅ |
| 阿里云盘开放平台 | `AliyundriveOpen` | `aliyundrive.zig` | ✅ |
| 夸克网盘 | `Quark`（Cookie） | `quarkuc.zig` | ✅ |
| 115 网盘 | `115 Cloud`（Cookie） | `pan115.zig` | ✅ |
| 联通沃云盘 WoPan | `WoPan`（refresh_token） | `wopan.zig` | ⚠️ 仅注册 + 单测，未真机（配置无凭据） |

**铁律**：`factory.key` 必须逐字节等于 Go 的 `driver.Config.Name`（即写进 `Storage.driver` 的字符串）；历史名只能进 `Factory.aliases`。
**故意不实现 copy**：itvsh / 123 / quark 上游 `Copy` 即 `NotSupport`，Zig 故意把 vtable `.copy` 置 `null`，并有显式测试钉住「别顺手补上」。

## 3. 验证结果

- **本机单测**：`328 passed / 3 skipped / 0 failed`（3 个 skip 是 itvsh 上传用例），无内存泄漏。
- **打包机 10.0.0.4 交叉编译**（目标 `aarch64-linux-musl`，加 `-lc -fstrip`）：`331 tests` 全过。
- **真机 e2e**（光猫，用户真实配置 10 存储）：**32 通过 / 0 失败 / 0 跳过** —— 9 挂载点全部列出、详情/下载/Range/sign 校验、WebDAV 读、Local 全量写操作 13 项全过。
- **最终 aarch64 二进制**：`1,144,432 B`（sha256 `d0c439…`）。

## 4. 本轮关键修复（2026-10-13 晚）

1. **sign 下载路由**：`/d/`、`/p/` 必须是**独立于 `handleAuthed`** 的路由（对齐 Go 的 Down 中间件）。曾挂在 `handleAuthed` 下，被开头的 `checkAuth` 401 拦掉，sign 体系形同虚设。已修，并加路由级回归测试（`/d/` 带合法 sign 无 token 必须放行；无 sign 无 token → 401）。
2. **Zig ↔ Go 重新核对**（7 个在用驱动：itvsh / webdav / 123Pan / aliyundrive / quark / 189pc / local）：云盘协议**全部 faithful**，其中 **189pc 的 HMAC/AES 签名逐字节验证一致**（安全关键）。修掉 2 个会动行为的差异：
   - Local `move` 缺 `IsSubPath(src,dst)` 防护（防把目录移进自己子树）→ 对齐 Go `driver.go:293`，已加守卫。
   - Quark `makeDir` 同名冲突返回 `NotSupported` → 改返回 `error.TargetExists`（api.zig `mapDriverError` → 409），对齐 Go `ObjectAlreadyExists`。
   - 余下 cosmetic 未动：aliyundrive 强制 `order_by` + link 缺 `Expiration`；Local `put` 不写 mtime —— 均不影响功能。

## 5. 工程约定（硬规则）

- **编译/测试/打包唯一交付路径 = 打包机 `10.0.0.4`**（Debian 13 x86_64，root/e3eb773F；zig 0.17.0 在 `/root/.cache`，只读使用；源码与独立缓存放 `/root/olz-*`）。**本机产物只能自测，不能当交付。**
- **Zig 0.17.0 硬下界**。本机路径 `C:/Users/Administrator/.workbuddy-ai/binaries/zig/0.17.0/`。
- **本机 D 盘不能 `zig build`**（maker.exe 无法在 D 盘建子进程）→ 一律 `zig build-exe`/`zig test` 直接调用 + 独立 `ZIG_GLOBAL_CACHE_DIR` + 非沙箱执行。
- **每个驱动必须有单元测试**（`std.testing.allocator` 抓泄漏）。提交前 `zig test` 与交叉编译都要过。
- **D 盘满 → 测试假报 NoSpaceLeft/泄漏**：先看磁盘，清理大头是 `openlist-zig/.zig-cache`（用 `cmd //c "rd /s /q"`，别用 Git Bash `rm -rf`）。
- **单测全绿 ≠ 能编出二进制**（Zig 按函数惰性分析，未触发的路径不实例化）—— 流程必须 test → build 都过。
- **上游唯一事实来源 = 本地 `D:\workspace\OpenList` 树**（`drivers/<name>/`）。不去 GitHub 拉；`itvsh` 是用户私有驱动，仅存在于本地树。

## 6. 真机部署（光猫 `192.168.1.1:10022`，隔离目录 `/tmp/olz`）

- **大二进制必须 SCP 传**（WinSCP SCP 协议，或 paramiko `scp -t` 模式）。SFTP 传 1.1MB 必断（EOFError）；10KB 配置正常。端口 `15344`（先 `netstat -ltn` 选空闲）。
- 设备 busybox 阉割：`chmod` **完全失效**（用 SFTP `sftp.chmod()`）；无 `pkill`/`stat`；ash 不支持 `for..do`；`umask` 恒 0；`base64` 不在 PATH。
- **只留一个进程**：SO_REUSEPORT 下多进程同监听同端口会被随机分发，造出「register 成功但 login 报 no administrator yet」假 bug。杀用 `kill -9`（SIGTERM 无效），杀完 `ps` + `netstat` 双确认。
- Zig 版显示前端须配**线上 CDN**（`cdn` + `web_version=rolling`，`dist_dir` 留空）：`https://cdn.jsdelivr.net/npm/@openlist-frontend/openlist-frontend@latest/dist`。
- 配置转换 `tools/import_go_config.py <go备份> <out.json>`；测完清理 `/tmp/olz` + 自进程，**绝不动 `/opt/sq/openlist` 与 Go 的 `config.json`/`data.db`**。

## 7. 下载签名 sign

- 算法逐字对齐 Go `pkg/sign/hmac.go`：带 padding 的 URL-safe base64(HMAC-SHA256) + `:expire`，`expire=0` 永不过期，secret 用 `jwt_secret`。config 新增 `sign_all` / `link_expiration`。
- `/d/`、`/p/` 独立于 `handleAuthed`（见 §4.1）。无 sign 无 token → 401；有合法 sign 无 token → 放行（对齐 Go `needSign`）。

## 8. WoPan 协议要点（联通沃云盘）

- 单一 `dispatcher` 入口（POST `panservice.mail.wo.cn/{channel}/dispatcher`，channel ∈ api-user / wohome）；header 签名 = `md5(key + resTime毫秒 + reqSeq + channel)` 小写 hex；body 的 `param` = AES-128-CBC + PKCS7（IV = `wNSOYIB1k1DjY5lA`；key：api-user 用 clientSecret `XFmi9GS2hzk98jGX`，wohome 用 accessToken 前 16 字节）后 base64；响应 `RSP.DATA` 若为 `"..."` 包裹的密文则同规则解密。上传走 `{zoneURL}/openapi/client/upload2C` 的 multipart。
- 注册名 `WoPan` 已进驱动表（共 10 驱动），但当前光猫配置无 wopan 存储实例（无 refresh_token），**未真机**。要验证需往 `/tmp/olz/config.json` 加一个 `WoPan` 存储后重启。

## 9. 未实现 / 功能边界

- 数据库与多用户体系、搜索、分享链接、后台任务/离线下载、归档解压与文件下载、远程归档浏览、远程 Range 的真正响应流式、完整设置/存储 CRUD、任务中心操作接口。
- **SFTP SSH 服务端：明确 defer**。单用户虽可缩授权范围（仅开放一个管理员账号、复用现有 `driver.Driver` vtable），但仍需 SSH transport + SFTP 协议，而 Zig 标准库无现成 SSH server，需移植/引依赖；恢复前应先选定可信 SSH 实现并以 OpenSSH/Paramiko 验证互通与 xz 体积，不直接自写密码学传输层。
- 上传进度 callback 全线接通（所有驱动按 Go `model.UpdateProgress` 报 0–100 百分比；itvsh 因并发上传用原子计数 + 独立轮询线程），但**尚无 `/api` 端点把它暴露给前端**。

## 10. 与上游代码对比（项目将作为 `D:\workspace\OpenList` 子目录）

> 用户计划把 `openlist-zig` 放进 `D:\workspace\OpenList` 作为子目录，紧挨 Go 的 `drivers/` 树，
> 方便逐文件比对。届时布局：
> - Zig：`D:\workspace\OpenList\openlist-zig\src\drivers\<name>.zig`
> - Go ：`D:\workspace\OpenList\drivers\<name>\`
>
> 快速逐驱动 diff（注意 Go 一个驱动是多文件，Zig 合并为单文件）：
>
> ```sh
> diff "D:/workspace/OpenList/openlist-zig/src/drivers/pan123.zig" "D:/workspace/OpenList/drivers/123/driver.go"
> ```
>
> 上游事实来源永远是**本地** OpenList 树，不要去 GitHub 拉；`itvsh` 仅本地存在。
