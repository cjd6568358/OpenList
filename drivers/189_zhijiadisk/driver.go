package zhijiadisk

import (
	"context"
	"net/http/cookiejar"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
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

	if d.UploadThread <= 0 {
		d.UploadThread = 3
	} else if d.UploadThread > 8 {
		d.UploadThread = 8
	}

	if d.AccessToken == "" {
		if d.Mobile == "" {
			return errs.EmptyUsername
		}
		if d.Password == "" {
			return errs.EmptyPassword
		}
		if err := d.login(ctx); err != nil {
			return err
		}
		op.MustSaveDriverStorage(d)
	}
	return d.refreshUserInfo(ctx)
}

func (d *ZhiJiaDisk) Drop(ctx context.Context) error {
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
