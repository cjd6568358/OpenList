package zhijiadisk

import (
	"context"
	"encoding/json"
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
	// 实测无需模拟小程序请求头（带上 servicewechat Referer 或 MicroMessenger UA
	// 反而会被 WAF 拦截）。保留 cookie jar 以自动接住上游下发的会话 cookie。
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	d.client = base.NewRestyClient().SetCookieJar(jar)

	// 回填上次持久化的会话 cookie，尽量免去重新登录
	d.restoreCookies()

	if d.UploadThread <= 0 {
		d.UploadThread = 3
	} else if d.UploadThread > 8 {
		d.UploadThread = 8
	}

	// 已有 access_token 就直接用；否则登录。
	// 注意 persistURLs 依赖 forwardUrl，此时它通常还是空的（首次配置时
	// 靠下面 refreshUserInfo 才拿到），所以恢复的 cookie 会先全部落在
	// apiBase 上；refreshUserInfo 之后会按真实 forwardUrl 再存一次。
	if d.AccessToken == "" {
		if d.Mobile == "" {
			return errs.EmptyUsername
		}
		if d.Password == "" {
			return errs.EmptyPassword
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
	jar := d.client.GetClient().CookieJar
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
