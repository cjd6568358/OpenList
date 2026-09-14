package zhijiadisk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// nasProxy 的 method 常量（对应小程序 config/nas.js）
const (
	methodFileList   = "capacity.nas.cloud.file.list"
	methodCreateDir  = "capacity.nas.cloud.file.dir.create"
	methodDeleteDir  = "capacity.nas.cloud.file.dir.delete"
	methodDeleteFile = "capacity.nas.cloud.file.delete"
	methodFileRename = "capacity.nas.cloud.file.rename"
	methodDirRename  = "capacity.nas.cloud.file.dir.rename"
	methodFileExist  = "capacity.nas.cloud.file.exist"
)

// 上传/下载时 uploadType 的取值
const (
	uploadTypeUpload   = 0
	uploadTypeDownload = 1
)

// ==================== 家庭共享（homeshare）处理 ====================
//
// 背景：服务端部分账号会在根目录返回一个名为「家庭共享」的目录，但它真正的
// 访问路径是 /homeshare（中文名只是显示名）。小程序里有两条防线：
//   1. renderPublicId：路径里出现「家庭共享」就替换成 homeshare，用于移动等
//      需要从 filename 拼路径的场景；
//   2. 列表渲染时若 API 没返回该目录，就硬编码塞一个 id=/homeshare 的假条目。
// 本项目账号实测根目录不返回它，故两条都做了轻量复刻。

const (
	homeshareName = "家庭共享"
	homesharePath = "/homeshare"
)

// normalizePath 把路径中的「家庭共享」段替换为 homeshare。
// 对不返回该目录的账号而言是空转，但换个账号就能避免拼出错误路径。
func normalizePath(p string) string {
	if p == "" || !strings.Contains(p, homeshareName) {
		return p
	}
	segments := strings.Split(p, "/")
	for i, seg := range segments {
		if seg == homeshareName {
			segments[i] = "homeshare"
		}
	}
	return strings.Join(segments, "/")
}

// homeshareEntry 构造列表里伪造的「家庭共享」条目。
// ID/Path 用 /homeshare（真实可访问路径），Name 用中文显示名。
func homeshareEntry() model.Obj {
	return &model.Object{
		ID:       homesharePath,
		Path:     homesharePath,
		Name:     homeshareName,
		IsFolder: true,
	}
}

// injectHomeshare 在根目录列表里补上「家庭共享」。
// 与小程序一致：API 返回了就用 API 的（并归一化其路径），没返回才伪造。
func injectHomeshare(objs []model.Obj) []model.Obj {
	for _, o := range objs {
		if o.GetName() == homeshareName || o.GetName() == "homeshare" {
			return objs
		}
	}
	return append([]model.Obj{homeshareEntry()}, objs...)
}

// ==================== 路径与解析工具 ====================

// joinPath 拼接父路径与子名，根目录下不产生重复斜杠
func joinPath(dir, name string) string {
	if dir == "" || dir == "/" {
		return "/" + name
	}
	return strings.TrimSuffix(dir, "/") + "/" + name
}

// parentPath 取父目录路径
func parentPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	parent := path.Dir(p)
	if parent == "." || parent == "" {
		return "/"
	}
	return parent
}

func queryEscape(s string) string {
	return url.QueryEscape(s)
}

func parseInt64(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseTime 解析秒级时间戳（10 位），也兼容毫秒级
func parseTime(s string) time.Time {
	sec := parseInt64(s)
	if sec == 0 {
		return time.Time{}
	}
	if sec < 1e12 {
		return time.Unix(sec, 0)
	}
	return time.UnixMilli(sec)
}

// ==================== 认证相关 ====================

// authHeaders 返回所有请求都要带的头。
// 注意不要加 Referer / MicroMessenger UA —— 会被上游 WAF 拦截。
func (d *ZhiJiaDisk) authHeaders() map[string]string {
	return map[string]string{
		"X-NAS-CLIENTTYPE": "60",
		"X-NAS-SDKTOKEN":   d.AccessToken,
	}
}

func (d *ZhiJiaDisk) forwardUrl() string {
	return strings.TrimSuffix(d.Addition.ForwardUrl, "/")
}

// rawPost 发一个带认证头的 JSON POST，返回通用信封（data 未解析）
func (d *ZhiJiaDisk) rawPost(ctx context.Context, url string, body interface{}, result interface{}) error {
	res, err := d.client.R().
		SetContext(ctx).
		SetHeaders(d.authHeaders()).
		SetBody(body).
		SetResult(result).
		Post(url)
	if err != nil {
		return err
	}
	if res.StatusCode() != 200 {
		return fmt.Errorf("request %s failed: HTTP %d, body: %s", url, res.StatusCode(), res.String())
	}
	return nil
}

// postEnvelope 发 JSON POST 并校验外层 code
func (d *ZhiJiaDisk) postEnvelope(ctx context.Context, url string, body interface{}) (*apiResp, error) {
	var resp apiResp
	if err := d.rawPost(ctx, url, body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 200 {
		return nil, fmt.Errorf("request %s failed: code %d, msg: %s", url, resp.Code, resp.Msg)
	}
	return &resp, nil
}

// login 用手机号+密码登录。
// 流程：取 AES 密钥 -> 加密密码 -> 提交登录。
func (d *ZhiJiaDisk) login(ctx context.Context) error {
	// 1. 取密钥
	keyResp, err := d.postEnvelope(ctx, apiBase+"/nas/session/key", base.Json{
		"mobile": d.Mobile,
	})
	if err != nil {
		return err
	}
	var secret string
	if err := json.Unmarshal(keyResp.Data, &secret); err != nil {
		return fmt.Errorf("parse session key failed: %w", err)
	}
	if secret == "" {
		return fmt.Errorf("session key is empty")
	}

	// 2. AES-ECB/Pkcs7 加密密码（输出小写 hex，与小程序 AES_encode 一致）
	encoded, err := aesEncodeHex(d.Password, secret)
	if err != nil {
		return fmt.Errorf("encrypt password failed: %w", err)
	}

	// 3. 登录
	loginResp, err := d.postEnvelope(ctx, apiBase+"/nas/user/login", base.Json{
		"mobile":    d.Mobile,
		"password":  encoded,
		"oauthType": "wx-small-app-Token",
	})
	if err != nil {
		return err
	}
	var data loginData
	if err := json.Unmarshal(loginResp.Data, &data); err != nil {
		return fmt.Errorf("parse login response failed: %w", err)
	}
	if data.AccessToken == "" {
		return fmt.Errorf("login failed: access_token is empty")
	}
	d.AccessToken = data.AccessToken
	if data.ForwardUrl != "" {
		d.Addition.ForwardUrl = data.ForwardUrl
	}
	return nil
}

// refreshUserInfo 拉取用户信息以补全 forwardUrl。
// forwardUrl 是上传/下载用的另一个域名，登录响应里不一定带。
func (d *ZhiJiaDisk) refreshUserInfo(ctx context.Context) error {
	infoResp, err := d.postEnvelope(ctx, apiBase+"/nas/user/info", base.Json{})
	if err != nil {
		return err
	}
	var data loginData
	if err := json.Unmarshal(infoResp.Data, &data); err != nil {
		return fmt.Errorf("parse user info failed: %w", err)
	}
	if data.ForwardUrl != "" {
		d.Addition.ForwardUrl = data.ForwardUrl
	}
	if d.forwardUrl() == "" {
		return fmt.Errorf("forwardUrl is empty, cannot upload or download")
	}
	return nil
}

// volumeInfo 取空间信息
func (d *ZhiJiaDisk) volumeInfo(ctx context.Context) (*volumeInfo, error) {
	resp, err := d.postEnvelope(ctx, apiBase+"/nas/volume/info", base.Json{})
	if err != nil {
		return nil, err
	}
	var info volumeInfo
	if err := json.Unmarshal(resp.Data, &info); err != nil {
		return nil, fmt.Errorf("parse volume info failed: %w", err)
	}
	return &info, nil
}

// ==================== 文件操作 ====================

// nasProxy 统一走 POST /nas/rd_center/data/get，body 为 {method, type, data}
func (d *ZhiJiaDisk) nasProxy(ctx context.Context, method string, data base.Json, typ ...int) (json.RawMessage, error) {
	t := 1
	if len(typ) > 0 {
		t = typ[0]
	}
	var inner nasResp
	if err := d.rawPost(ctx, apiBase+"/nas/rd_center/data/get", base.Json{
		"method": method,
		"type":   t,
		"data":   data,
	}, &inner); err != nil {
		return nil, err
	}
	if inner.Code != 200 {
		return nil, fmt.Errorf("%s failed: code %d, msg: %s", method, inner.Code, inner.Msg)
	}
	if inner.Data.ErrorCode != "0" {
		msg := inner.Data.ErrorMsg
		if msg == "" {
			msg = fmt.Sprintf("errorCode %s", inner.Data.ErrorCode)
		}
		return nil, fmt.Errorf("%s failed: %s", method, msg)
	}
	return inner.Data.Data, nil
}

// list 列出目录下的文件与目录
func (d *ZhiJiaDisk) list(ctx context.Context, dir string) ([]fileEntry, error) {
	if dir == "" {
		dir = "/"
	}
	raw, err := d.nasProxy(ctx, methodFileList, base.Json{
		"directory": normalizePath(dir),
		"limit":     10000,
		"offset":    0,
	})
	if err != nil {
		return nil, err
	}
	var entries []fileEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse file list failed: %w", err)
	}
	return entries, nil
}

// getToken 换取上传/下载 token。
// 该接口要求 form-urlencoded，且 pathFileName 不做 URL 编码（与小程序一致）。
func (d *ZhiJiaDisk) getToken(ctx context.Context, pathFileName string, uploadType int) (string, error) {
	var resp apiResp
	res, err := d.client.R().
		SetContext(ctx).
		SetHeaders(d.authHeaders()).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"pathFileName": normalizePath(pathFileName),
			"uploadType":   strconv.Itoa(uploadType),
		}).
		SetResult(&resp).
		Post(apiBase + "/nas/user/upload/userInfo")
	if err != nil {
		return "", err
	}
	if res.StatusCode() != 200 || resp.Code != 200 {
		return "", fmt.Errorf("get upload token failed: HTTP %d, code %d, body: %s",
			res.StatusCode(), resp.Code, res.String())
	}
	var token string
	if err := json.Unmarshal(resp.Data, &token); err != nil {
		// 兼容 data 直接是字符串但带转义的情况
		var s string
		if err2 := json.Unmarshal(resp.Data, &s); err2 == nil {
			token = s
		} else {
			return "", fmt.Errorf("parse upload token failed: %w, data: %s", err, string(resp.Data))
		}
	}
	if token == "" {
		return "", fmt.Errorf("upload token is empty, data: %s", string(resp.Data))
	}
	return token, nil
}

// fileExist 检查目录下是否已存在同名文件
func (d *ZhiJiaDisk) fileExist(ctx context.Context, dir, name string) (bool, error) {
	raw, err := d.nasProxy(ctx, methodFileExist, base.Json{
		"directory": dir,
		"filename":  name,
	})
	if err != nil {
		return false, err
	}
	var exists bool
	if err := json.Unmarshal(raw, &exists); err != nil {
		return false, nil
	}
	return exists, nil
}
