package zhijiadisk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
)

// API 主机固定，上传/下载走登录后返回的 forwardUrl（另一个域名）。
const (
	apiBase = "https://pan.itvsh.cn"
	// 上传/下载路径，拼在 forwardUrl 之后
	pathPutFile  = "/nasforward/file/binary/upload"
	pathDownload = "/nasforward/file/download"
	// 分块大小，与小程序 / web 版一致
	chunkSize = 512 * 1024
)

type ZhiJiaDisk struct {
	model.Storage
	Addition

	// client 带 cookie jar：上游会在响应里下发会话 cookie，
	// 交给 jar 自动维护，避免每次请求都重新协商。
	client *resty.Client

	// jar 就是 client 用的那个 cookie jar，单独留个引用便于读写与持久化
	// （http.Client 的字段名是 Jar，直接从 client 上捞比较绕）。
	jar *cookiejar.Jar

	// authMu 串行化「重新登录 / 刷新会话」，避免并发请求同时触发多轮登录。
	authMu sync.Mutex
}

func (d *ZhiJiaDisk) Config() driver.Config {
	return config
}

func (d *ZhiJiaDisk) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *ZhiJiaDisk) Init(ctx context.Context) error {
	// 上游挂着瑞数（RiverSecurity）系 WAF，对请求头极其敏感。
	// 参考 mp_zhijiadisk/web/proxy-server.js 里已趟平的结论：
	//   - 带 MicroMessenger / 微信小程序 UA 会被直接打回 412
	//   - 带 servicewechat 的 Referer 同样触发挑战
	//   - 伪装成浏览器的 UA（base.NewRestyClient 默认那个带 OpenList 指纹的）
	//     也是挑战目标，所以这里整体清空 UA，只留最小头集合
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	d.jar = jar
	// base.NewRestyClient() 默认会设一个伪装成浏览器的 UA（含 OpenList 指纹），
	// 那是 WAF 的重点目标。这里在真正发车前把它清成空串 ——
	// Go 的 net/http 对「存在但为空」的 User-Agent 会整个省略该头，
	// 正好对齐 Web 版「不发 UA」的做法。
	// 用 pre-request hook 而不是 SetHeader，是为了绕开 resty 对空值 header
	// 的潜在忽略，直接作用到最终的 *http.Request 上。
	d.client = base.NewRestyClient().
		SetCookieJar(jar).
		SetPreRequestHook(func(_ *resty.Client, req *http.Request) error {
			req.Header.Set("User-Agent", "")
			req.Header.Del("Referer")
			req.Header.Del("Origin")
			req.Header.Del("X-Requested-With")
			return nil
		})

	// 回填上次持久化的会话 cookie，尽量免去重新登录
	d.restoreCookies()

	// 兜底 5，与表单默认值、以及官方客户端的 maxConcurrency 保持一致。
	// 表单的 default 只在新建时生效，老配置里 upload_thread 可能是 0。
	if d.UploadThread <= 0 {
		d.UploadThread = 5
	} else if d.UploadThread > 8 {
		d.UploadThread = 8
	}

	// 已有 access_token 就直接用；否则登录。
	// 注意 persistURLs 依赖 forwardUrl，此时它通常还是空的（首次配置时
	// 靠下面 refreshUserInfo 才拿到），所以恢复的 cookie 会先全部落在
	// apiBase 上；refreshUserInfo 之后会按真实 forwardUrl 再存一次。
	// 无 token 时只能走账密登录（表单层已允许两者都留空，故这里必须显式拦下，
	// 否则会拿空账号去请求，报出难以理解的业务错误）。
	// 这里不用 errs.EmptyUsername/EmptyPassword：那是通用文案（"username is empty"），
	// 在「二选一」语义下说不清到底该补哪一边。
	if d.AccessToken == "" {
		if d.Mobile == "" || d.Password == "" {
			return errors.New("请填写手机号+密码，或填写 Access token（二选一）")
		}
		if err := d.login(ctx); err != nil {
			// 有持久化的会话 cookie 时，即使密码登录失败也能凭 cookie 继续
			// （例如密码已改）。此时不再向上报错，交给后续请求自愈。
			if !d.hasCookies() {
				return err
			}
			utils.Log.Warnf("[zhi] login failed, fallback to persisted cookies: %v", err)
		}
		op.MustSaveDriverStorage(d)
	}
	if err := d.refreshUserInfo(ctx); err != nil {
		return err
	}
	// 到这里 forwardUrl 已就绪，把 cookie 按正确的域名作用域重新回填并落库，
	// 否则下次启动 persistURLs 仍拿不到 forwardUrl，cookie 会被丢在错误的 host 下。
	d.regraftCookies()
	if d.saveCookies() {
		op.MustSaveDriverStorage(d)
	}
	return nil
}

// regraftCookies 在 forwardUrl 就绪后，把已持久化的 cookie 重新回填到
// 正确的作用域上。Init 早期 forwardUrl 为空，jar 里只认 apiBase，
// 这里补上 forwardUrl 对应的 host。
func (d *ZhiJiaDisk) regraftCookies() {
	if d.Addition.Cookies == "" || d.forwardUrl() == "" {
		return
	}
	var cookies []*http.Cookie
	if err := json.Unmarshal([]byte(d.Addition.Cookies), &cookies); err != nil || len(cookies) == 0 {
		return
	}
	jar := d.jar
	if jar == nil {
		return
	}
	if u, err := url.Parse(d.forwardUrl()); err == nil {
		jar.SetCookies(u, cookies)
	}
}

func (d *ZhiJiaDisk) Drop(ctx context.Context) error {
	d.authMu.Lock()
	// 停用/重载时尽量把会话 cookie 存下来
	if d.saveCookies() {
		op.MustSaveDriverStorage(d)
	}
	d.authMu.Unlock()
	return nil
}

func (d *ZhiJiaDisk) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	entries, err := d.list(ctx, dir.GetPath())
	if err != nil {
		return nil, err
	}
	objs := make([]model.Obj, 0, len(entries)+1)
	for i := range entries {
		objs = append(objs, entries[i].obj())
	}
	// 根目录补上「家庭共享」（服务端不一定返回它，小程序也是客户端伪造的）
	if dir.GetPath() == "/" || dir.GetPath() == "" {
		objs = injectHomeshare(objs)
	}
	return objs, nil
}

// Link 取下载直链。除 URL 外还必须带上 X-NAS-SDKTOKEN 头，
// 因此把 header 一并返回，由 OpenList 代理下载时携带。
func (d *ZhiJiaDisk) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	token, err := d.getToken(ctx, file.GetPath(), uploadTypeDownload)
	if err != nil {
		return nil, err
	}
	url := d.forwardUrl() + pathDownload +
		"?filenamepath=" + queryEscape(normalizePath(file.GetPath())) +
		"&offset=0&bufsize=" +
		"&fileName=" + queryEscape(file.GetName()) +
		"&uploadToken=" + token

	header := make(map[string][]string)
	for k, v := range d.authHeaders() {
		header[k] = []string{v}
	}
	// 下载由 OpenList 代为发起，同样不认我们的 jar，需把 WAF 挑战 cookie 一并返回
	if ck := d.cookieHeader(url); ck != "" {
		header["Cookie"] = []string{ck}
	}
	return &model.Link{URL: url, Header: header}, nil
}

// MakeDir 新建目录。注意接口收的是**完整路径**，不是「父目录+名字」。
func (d *ZhiJiaDisk) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	_, err := d.nasProxy(ctx, methodCreateDir, base.Json{
		"directory": normalizePath(joinPath(parentDir.GetPath(), dirName)),
	})
	return err
}

// Rename 重命名。文件与目录都用 file.rename（与小程序一致）。
func (d *ZhiJiaDisk) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	_, err := d.nasProxy(ctx, methodFileRename, base.Json{
		"directory":   normalizePath(parentPath(srcObj.GetPath())),
		"filename":    srcObj.GetName(),
		"newFilename": newName,
	})
	return err
}

// Move 移动。服务端没有独立 move 接口，移动即「按路径改路径」：
// 把 directory 改成含文件名的完整新路径 newDirectory。
func (d *ZhiJiaDisk) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	src := normalizePath(srcObj.GetPath())
	// 注意目标路径用源节点的 Name 拼接，需归一化以免拼出「家庭共享」
	target := normalizePath(joinPath(dstDir.GetPath(), srcObj.GetName()))
	if target == src {
		return errs.NotSupport
	}
	_, err := d.nasProxy(ctx, methodDirRename, base.Json{
		"directory":    src,
		"newDirectory": target,
	})
	return err
}

// Copy 服务端未提供任何复制接口（已遍历全部 method 确认），无法实现。
func (d *ZhiJiaDisk) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return errs.NotSupport
}

func (d *ZhiJiaDisk) Remove(ctx context.Context, obj model.Obj) error {
	if obj.IsDir() {
		_, err := d.nasProxy(ctx, methodDeleteDir, base.Json{
			"directory": normalizePath(obj.GetPath()),
		})
		return err
	}
	_, err := d.nasProxy(ctx, methodDeleteFile, base.Json{
		"directory": normalizePath(parentPath(obj.GetPath())),
		"filename":  obj.GetName(),
	})
	return err
}

func (d *ZhiJiaDisk) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	return d.upload(ctx, dstDir, stream, up)
}

func (d *ZhiJiaDisk) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	info, err := d.volumeInfo(ctx)
	if err != nil {
		return nil, err
	}
	total := info.Capacity
	if total == 0 {
		total = info.Size
	}
	used := info.CapacityUsed
	if used == 0 {
		used = info.UserSize
	}
	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: total,
			UsedSpace:  used,
		},
	}, nil
}
var _ driver.Driver = (*ZhiJiaDisk)(nil)
