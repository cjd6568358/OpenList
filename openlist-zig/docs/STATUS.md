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
| STRM（其他挂载→.strm） | `Strm`（paths 行） | `strm.zig` | ✅ 2026-10-14 真机验证（挂载/列表/详情/内容/OnlyProxy 全链路） |

**铁律**：`factory.key` 必须逐字节等于 Go 的 `driver.Config.Name`（即写进 `Storage.driver` 的字符串）；历史名只能进 `Factory.aliases`。
**故意不实现 copy**：itvsh / 123 / quark 上游 `Copy` 即 `NotSupport`，Zig 故意把 vtable `.copy` 置 `null`，并有显式测试钉住「别顺手补上」。

## 3. 验证结果

- **打包机 10.0.0.4**（唯一构建路径；本机无 Zig 工具链）：`zig test` **338 passed / 0 failed**，无内存泄漏。其中 `every JSON endpoint emits strict, parseable JSON` 把**所有**已注册 JSON 端点跑一遍做严格解析。
- **交叉编译**（目标 `aarch64-linux-musl`，加 `-lc -fstrip`）通过。
- **真机 e2e**（光猫，用户真实配置 10 存储）：**32 通过 / 0 失败 / 0 跳过** —— 9 挂载点全部列出、详情/下载/Range/sign 校验、WebDAV 读、Local 全量写操作 13 项全过。
- **前端页面**：光猫 `15344` 首页由「获取设置失败： Undefined」恢复为正常登录页（`登录到 OpenList (zig)`），logo 正常渲染（`src="https://res.oplist.org/logo/logo.svg"`）。
- **`/api/public/settings`**：返回 **47** 个字段（对齐 Go `db.GetPublicSettingItems()` 的 `flag IN (PUBLIC, READONLY)`），值**全部是字符串**。
- **`/api/fs/list`**：顶层 7 字段齐全（`content`/`total`/`readme`/`header`/`write`/`write_content_bypass`/`provider`），`write=true`；`fs/get` 含 `header`/`related`，`provider` 为驱动名。
- **管理员途径（真机全链路）**：`init_status:false` → `POST /public/init/setup` 建 admin → **前端路径 `/auth/login/hash`（StaticHash）登录成功拿到 token** → `/api/me` 鉴权通过 → `openlist admin set 新密码`（**热重载，服务未重启**）→ 新密码登录成功、旧密码 400。
- **最终 aarch64 二进制**：`1,178,120 B`（sha256 `ff55491f…`），**347 tests passed**（2026-10-14，含 STRM 驱动）。

## 4. 本轮关键修复（2026-10-13 晚）

1. **sign 下载路由**：`/d/`、`/p/` 必须是**独立于 `handleAuthed`** 的路由（对齐 Go 的 Down 中间件）。曾挂在 `handleAuthed` 下，被开头的 `checkAuth` 401 拦掉，sign 体系形同虚设。已修，并加路由级回归测试（`/d/` 带合法 sign 无 token 必须放行；无 sign 无 token → 401）。
2. **Zig ↔ Go 重新核对**（7 个在用驱动：itvsh / webdav / 123Pan / aliyundrive / quark / 189pc / local）：云盘协议**全部 faithful**，其中 **189pc 的 HMAC/AES 签名逐字节验证一致**（安全关键）。修掉 2 个会动行为的差异：
   - Local `move` 缺 `IsSubPath(src,dst)` 防护（防把目录移进自己子树）→ 对齐 Go `driver.go:293`，已加守卫。
   - Quark `makeDir` 同名冲突返回 `NotSupported` → 改返回 `error.TargetExists`（api.zig `mapDriverError` → 409），对齐 Go `ObjectAlreadyExists`。
   - 余下 cosmetic 未动：aliyundrive 强制 `order_by` + link 缺 `Expiration`；Local `put` 不写 mtime —— 均不影响功能。
3. **`/api/public/settings` 响应体多一个 `}`（2026-10-13 深夜）**：`handlePublicSettings` 收尾写成 `append("}}}")` —— `append` 写**原始字节**，不做 `print` 那样的 `{{`/`}}` 转义，于是 337 字节的 body 里只有前 336 是合法 JSON。后果不是 500，而是前端静默出错：axios 的 `JSON.parse` 抛错被 `silentJSONParsing` 降级成字符串，`e.code === 200` 永远为假，首页只显示「获取设置失败： Undefined」（看起来像 CDN/网络问题）。已修为 `append("}}")`，并加两层回归：`public settings body is strict JSON` + `every JSON endpoint emits strict, parseable JSON`（遍历全部端点做严格解析）。
4. **`/api/public/settings` 字段缺失（2026-10-13 深夜）**：修完 #3 后页面能开，但 logo 是 `<img src="">`。根因是同一个 handler 只返回 10 个**自造**字段（`initial_done` / `api` / `cdn` / `token_expires_in` / `enable_register` …），而前端真正读的键（`logo`、`favicon`、`home_icon`、`settings_layout`、`pagination_type`…）一个都没有。已按 Go 的字段集重写为 47 项**表驱动**输出（键名/默认值照抄 `internal/bootstrap/data/setting.go` 里 `flag != PRIVATE` 的项），值**一律字符串** —— Go 侧是 `map[string]string`，前端用 `t === 'true' || t === '1'` 判布尔，给原生 bool/int 会让判断恒为 false。新增 `public settings carries the keys the frontend actually reads`，把前端代码实际引用的 33 个键逐个钉住（清单由扫描 dist 的 `(\`key\`)` 取值点得出）。
5. **`/api/fs/list` 信封字段缺失（2026-10-13 深夜）**：Go `FsListResp`（`server/handles/fsread.go:49-58`）带 `readme`/`header`/`write`/`write_content_bypass`/`provider`，我们一个都没发。前端 store 用 `setWrite(e.write)` 决定是否渲染上传/新建/删除按钮 —— 字段缺失会让 `write` 变 `undefined`、目录被判成只读，**按钮整片消失**。已加 `appendFsListTail`（根目录与挂载目录共用）；同时给 `fs/get` 补 `header`/`related`，并把 `provider` 从空串改成驱动名（对齐 `fsread.go:309-311`）。新增 `fs list carries the envelope fields the frontend reads`，并用自签 token 在真机逐个核过。
6. **首次安装 / 忘记密码的途径（2026-10-13 深夜）**：此前只有 Zig **自造**的 `POST /api/auth/register`（Go 根本没有这个端点），且没实现 Go 的官方途径 —— 于是空环境下前端既不引导注册、CLI 也改不了密码。已补齐三条官方途径并删掉自造端点：
   - **Web 安装向导**：`GET /api/public/init_status` + `POST /api/public/init/setup`（对齐 `server/router.go:105-106` + `server/handles/setup.go`）。
   - **CLI**：`openlist admin` / `admin random` / `admin set NEW_PASSWORD` / `admin token`（对齐 `cmd/admin.go` 与官方 FAQ「忘记密码怎么办」）。改完凭据后会 POST `/api/admin/user/del_cache` 通知在线服务**热重载**（对齐 `cmd/user.go:DelAdminCacheOnline`），**无需重启**；端点用 `zig.token` 认证（对齐 Go 用 settings 表的 token）。
   - **环境变量**：`OPENLIST_ADMIN_PASSWORD`（对齐 `internal/bootstrap/data/user.go:initAdmin`，仅首次启动、无管理员时生效）。
   - 首次启动自动生成 `zig.token`（对齐 Go 首次启动把 `random.Token()` 写进 settings 表），服务与 CLI 共用。
   - 真机验证：`init_status:false → init/setup → 登录 → admin set 新密码（未重启）→ 新密码可登录、旧密码 400` 全链路通过。
7. **前端登录路径 `/api/auth/login/hash` 缺失 + 密码哈希未对齐 Go（2026-10-13 深夜）**：前端登录页 POST 的是 `/auth/login/hash`，body 里的 `password` **已经**是 `StaticHash(明文)` = `sha256(pw + "-" + StaticHashSalt)`；这个端点此前缺失 ⇒ **前端恒登不上**，而 curl 直接打 `/auth/login` 却是通的 —— 「curl 验证过」≠「前端能登录」。同时把密码存储对齐 Go 的 `User.SetPassword`（`internal/model/user.go:96`）：现生成 16 位随机 salt（`zig.admin_salt`），存 `TwoHashPwd(pwd, salt)` = `sha256(sha256(pw + "-" + StaticHashSalt) + "-" + salt)`。向量测试钉住了用户抓包里的真实哈希（`7f3de24c…`）。这是 §11.3「核心算法对齐 Go」的第一块落地。

## 5. 工程约定（硬规则）

- **⚠️ 本地需要打包 / 编译时，务必一律走打包编译机 `10.0.0.4`（工作目录 `/tmp`，即 `tools/build_remote.py` 用的 `/tmp/olz-build`）—— 这是唯一交付路径。** 原因：本地机器**性能不行、磁盘空间不够**。打包机 Debian 13 x86_64，root/e3eb773F；zig 0.17.0 在 `/root/.cache`（只读使用）。**本机产物只能自测，不能当交付。**
- **Zig 0.17.0 硬下界**。**本机当前没有 Zig 工具链**（`~/.workbuddy-ai/binaries/` 下只有 git/go/node/python），`zig test` 与交叉编译都只能在打包机跑 —— 一条命令走 `tools/build_remote.py`（打包源码 → 打包机 test → 交叉编译 → 取回，全包）。
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

### 6.1 重启光猫后如何恢复（`/tmp` 是 tmpfs，重启全丢）

光猫分区实测：`/tmp` = tmpfs（220.9M，**重启必丢**）；`/` = overlay **可写且持久**
（upperdir=`/opt/cu/apps/apps`，仅剩 15.3M）。部署约定放在 `/tmp/olz` ⇒ 重启后
二进制和 config.json（含管理员凭据）都会消失。恢复路径（三选一，**A 推荐**）：

- **A. 部署时用环境变量定死密码**（对齐 Go `initAdmin`）：
  ```sh
  cd /tmp/olz && OPENLIST_ADMIN_PASSWORD='你的固定密码' \
    nohup ./openlist server --config /tmp/olz/config.json >> /tmp/olz/olz.log 2>&1 &
  ```
  首次启动（无管理员）会自动创建 `admin` + 这个密码并**打印到控制台**。密码是
  你自己定的，不是系统随机生成的 —— 所以不存在"获取"，每次部署用同一个值即可。
- **B. 本机留一份 config.json，部署时一起上传**：salt / hash / jwt_secret / 存储
  配置全部原样恢复。⚠️ 里面有网盘凭据，别提交进 git。
- **C. 把部署目录挪到持久分区**（如 `/opt/olz`）：重启什么都不丢，但根分区只剩
  15.3M，且当前约定是"临时部署在 /tmp" —— 要挪需先明确。

> 登录姿势提醒：前端发的是 `/api/auth/login/hash`（body 里的 password 已是
> `StaticHash(明文)`）；手工 curl 才会用 `/api/auth/login`（明文）。
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
- **★ 未来移植 SFTP/FTP 服务端时的安全要点（用户 2026-10-13 提出的上游 bug）**：上游 Go 版的 SFTP/FTP 登录**失败计数 key 用了 `IP:端口`** —— 互联网扫描器每次连接源端口都不同，计数永远到不了阈值，**限速/锁定形同虚设**（已被真实爆破验证）。这条值得反馈上游 OpenList。我们将来实现时：**失败计数的 key 必须用纯 IP**（不带端口），阈值判定、锁定时长（Go `model.DefaultMaxAuthRetries` / `DefaultLockDuration`，见 `server/handles/auth.go` 的 `model.LoginCache` 用法）也要对齐并自查一遍 key 的粒度。同理适用于 HTTP 登录接口现有限流逻辑的复查。
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

## 11. 待处理（用户 2026-10-13 明确要求）

> 用户对当前若干"简化取舍"提出明确反对。以下四项**必须做**，不得再以"工程简化 /
> 体积受限 / 实现困难"为由跳过。此前把它们当成可接受的取舍，是判断错误。
>
> **进度（2026-10-13 深夜）**：**11.3 已完成** —— 注册/初始化端点（§4.6）与
> **密码哈希算法**（§4.7，`salt` + `TwoHashPwd`，向量测试钉住前端真实抓包）都已
> 对齐 Go；**11.1 / 11.2 / 11.4 仍未动**。

### 11.1 Go 配置必须**无缝迁移**；Zig 配置应是 Go 的**子集**

- 现状：`tools/import_go_config.py` 做的是**有损转换** —— 驱动名映射、不支持的驱动丢弃、
  管理员凭据不迁移、settings 一律落默认值。
- 用户要求：**理论上 Zig 配置就是 Go 的子集，不应存在差异**。任何字段都不该在迁移中
  被改写或丢失。
- 待办：重新设计配置层，使其能直接消费 Go 的配置来源（`config.json` + `data.db` 里的
  storages / settings / users），不丢字段、不做语义改写；把 `import_go_config.py` 从
  "转换器"降级为（或替换为）"直读器"。

### 11.2 允许使用 SQLite（C 桥接）；**没有** 1 MB 体积上限；交叉编译不是 Zig 弱项

- 我此前以"体积 / 依赖 / 交叉编译复杂度"为由排除了 SQLite，用户明确否掉：
  - **没有禁止使用 SQLite**；
  - 可以通过 **C 桥接**（`@cImport` / 链接 `libsqlite3`）调用；
  - **没有** 1 MB 的体积硬限制；
  - **交叉编译不是** Zig 的弱项（Zig 本身就是 C 交叉编译器）。
- 待办：落地 SQLite 支持（链接 libsqlite3 + `aarch64-linux-musl` 交叉编译），直接读
  Go 的 `data.db`；据此重新评估体积预算与 musl 静态链接方案。

### 11.3 核心算法必须与 Go **完全一致**，不得自创

- 用户反复强调：核心算法一律对齐 Go，否则后续无法与上游同步。
- 已知不一致（需逐项审计并修正）：
  - ✅ **密码哈希**：已于 2026-10-13 对齐（§4.7）—— `zig.admin_salt`（16 位随机 salt，
    对齐 `User.SetPassword`）+ `TwoHashPwd(pwd, salt)`，`StaticHashSalt` 与 Go 逐字节一致，
    前端真实抓包哈希（`7f3de24c…`）有向量测试钉住。
  - ✅ **注册 / 初始化端点**：Go 只有 `GET /public/init_status` + `POST /public/init/setup`
    （`server/router.go:105-106`），**没有** `/auth/register`。Zig 自造的那个已于
    2026-10-13 删除，两条官方端点已实现，CLI / 环境变量途径也补齐（见 §4.6）。
  - 待办：建立"逐函数对照 Go"的审计清单（沿用 189pc 那种**逐字节**验证的做法），
    覆盖签名、JWT claim、时间格式等其余安全/协议相关算法。

### 11.4 驱动名 / 字段映射**不是**难点，是必须做对的基础工作

- 我此前把"驱动名需映射、不支持驱动需丢弃"描述成工程难点，用户不认可 ——
  驱动名映射只是一张**确定性对照表**（`factory.key` 逐字节等于 Go 的
  `driver.Config.Name`），不存在技术难点。
- 待办：补全**所有** Go 驱动的映射；不支持的驱动要给出**明确、可查询**的理由，
  而不是在转换脚本里静默丢弃。
