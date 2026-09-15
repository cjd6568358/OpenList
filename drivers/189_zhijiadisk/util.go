package zhijiadisk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
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

// 鉴权失效的识别。上游把「token 过期」表示为 code 1009/1011 或 msg 里的文案，
// 这里按同样的口径判定，命中则触发会话恢复。
var authFailureCodes = []int{1009, 1011, 401}

var authFailureMarkers = []string{
	"token expired",
	"token过期",
	"upload/download token expired",
	"登录已过期",
	"未登录",
}

// isAuthFailure 判断错误是否属于「会话失效、可自动恢复」
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, c := range authFailureCodes {
		if strings.Contains(msg, strconv.Itoa(c)) {
			// code 以「code 1009」形式出现，避免误伤正文里恰好含这些数字的情况
			if strings.Contains(msg, "code "+strconv.Itoa(c)) {
				return true
			}
		}
	}
	for _, m := range authFailureMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

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
// 只保留上游必需的 X-NAS-* 与一个语言标记；其余一律从简 ——
// 上游 WAF 对多余/伪装的头部很敏感，见 Init 里的说明。
func (d *ZhiJiaDisk) authHeaders() map[string]string {
	return map[string]string{
		"X-NAS-CLIENTTYPE": "60",
		"X-NAS-SDKTOKEN":   d.AccessToken,
		"Accept-Language":  "zh-cn",
	}
}

func (d *ZhiJiaDisk) forwardUrl() string {
	return strings.TrimSuffix(d.Addition.ForwardUrl, "/")
}

// cookieHeader 从 jar 里取出适用于 target 的 cookie，拼成 Cookie 头。
//
// 为什么需要它：WAF 首次 200 会种一颗挑战 cookie，之后**每个**请求都得带上，
// 否则会被重新挑战（对照 web/proxy-server.js:62 的 wafCookies 逻辑）。
// resty 那条路径由 SetCookieJar 自动处理，但上传走的是 base.HttpClient、
// 下载是 OpenList 拿 URL 自己去请求，两者都不认识我们的 jar，必须手动补。
func (d *ZhiJiaDisk) cookieHeader(target string) string {
	if d.jar == nil || target == "" {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	cookies := d.jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// ==================== 会话 cookie 持久化 ====================
//
// 登录态实际由 cookie 维持：token 失效（1009）时上游是**不带密码**重取用户信息恢复的，
// 说明会话上下文在 cookie 里。只把 jar 放内存，进程一重启就丢，会话随之失效。
// 这里把 jar 序列化进 Addition，随存储配置一起落库。

// persistURLs 是 jar 的“作用域种子”。jar 以 host 为键收集 cookie，
// 恢复时得先知道该往哪些 host 回填 —— 这两个正是本驱动会访问的域名。
func (d *ZhiJiaDisk) persistURLs() []*url.URL {
	urls := make([]*url.URL, 0, 2)
	for _, raw := range []string{apiBase, d.forwardUrl()} {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err == nil {
			urls = append(urls, u)
		}
	}
	return urls
}

// hasCookies 是否已有可复用的会话 cookie
func (d *ZhiJiaDisk) hasCookies() bool {
	return d.Addition.Cookies != "" && len(d.persistURLs()) > 0
}

// saveCookies 把 jar 内容序列化进 Addition。
// 返回是否有变化，避免每次请求都写库。
func (d *ZhiJiaDisk) saveCookies() bool {
	jar := d.jar
	if jar == nil {
		return false
	}
	var all []*http.Cookie
	for _, u := range d.persistURLs() {
		all = append(all, jar.Cookies(u)...)
	}
	if len(all) == 0 {
		return false
	}
	// 用 cookiejar.Options 同款 JSON 编码，便于跨版本稳定
	encoded, err := json.Marshal(all)
	if err != nil {
		return false
	}
	if string(encoded) == d.Addition.Cookies {
		return false
	}
	d.Addition.Cookies = string(encoded)
	return true
}

// restoreCookies 在 Init 时把上次存的 cookie 回填进 jar。
// 内容损坏时静默跳过并清空，退化为重新登录，不影响可用性。
func (d *ZhiJiaDisk) restoreCookies() {
	if d.Addition.Cookies == "" {
		return
	}
	var cookies []*http.Cookie
	if err := json.Unmarshal([]byte(d.Addition.Cookies), &cookies); err != nil {
		utils.Log.Warnf("[zhi] restore cookies failed, will login again: %v", err)
		d.Addition.Cookies = ""
		return
	}
	if len(cookies) == 0 {
		return
	}
	jar := d.jar
	if jar == nil {
		return
	}
	for _, u := range d.persistURLs() {
		jar.SetCookies(u, cookies)
	}
}

// relogin 在业务请求因鉴权失效失败时恢复会话，全程无用户介入。
// 顺序与上游一致：先用会话 cookie 重取用户信息（不带密码），
// 不行再用已存密码重新登录。
func (d *ZhiJiaDisk) relogin(ctx context.Context) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	if d.hasCookies() {
		if err := d.refreshSession(ctx); err == nil {
			return nil
		} else {
			utils.Log.Warnf("[zhi] refresh session with cookies failed: %v", err)
		}
	}
	if d.Mobile == "" || d.Password == "" {
		return errs.EmptyPassword
	}
	if err := d.login(ctx); err != nil {
		return err
	}
	if err := d.refreshUserInfo(ctx); err != nil {
		return err
	}
	op.MustSaveDriverStorage(d)
	return nil
}

// withRelogin 执行 fn；判定为鉴权失效时恢复会话并重试一次。
//
// 注意：fn 内部只允许走 nasProxy（业务接口），**绝不能**间接调用 login，
// 否则会与 relogin 形成无限递归。
func (d *ZhiJiaDisk) withRelogin(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil || !isAuthFailure(err) {
		return err
	}
	utils.Log.Warnf("[zhi] auth failed, restoring session: %v", err)
	if rerr := d.relogin(ctx); rerr != nil {
		// 恢复失败时返回原始错误，更有诊断价值
		utils.Log.Errorf("[zhi] restore session failed: %v", rerr)
		return err
	}
	return fn()
}

// refreshSession 凭已存的会话 cookie 重新拉取用户信息。
// token 失效（1009）时上游就是这么恢复的：不带密码，只靠 cookie。
// 成功即说明会话仍然有效，调用方可以据此重试原请求。
func (d *ZhiJiaDisk) refreshSession(ctx context.Context) error {
	if err := d.refreshUserInfo(ctx); err != nil {
		return err
	}
	op.MustSaveDriverStorage(d)
	return nil
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
		// 412 是瑞数 WAF 的挑战响应（响应体是一段动态混淆 JS，不是业务 JSON）。
		// 单列出来，免得再被当成「接口返回异常」排查。
		if res.StatusCode() == http.StatusPreconditionFailed {
			return fmt.Errorf("request %s failed: 被上游 WAF 拦截 (HTTP 412)", url)
		}
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

// nasProxy 统一走 POST /nas/rd_center/data/get，body 为 {method, type, data}。
// 鉴权失效时自动恢复会话并重试一次。
func (d *ZhiJiaDisk) nasProxy(ctx context.Context, method string, data base.Json, typ ...int) (json.RawMessage, error) {
	t := 1
	if len(typ) > 0 {
		t = typ[0]
	}
	var raw json.RawMessage
	err := d.withRelogin(ctx, func() error {
		var inner nasResp
		if err := d.rawPost(ctx, apiBase+"/nas/rd_center/data/get", base.Json{
			"method": method,
			"type":   t,
			"data":   data,
		}, &inner); err != nil {
			return err
		}
		if inner.Code != 200 {
			return fmt.Errorf("%s failed: code %d, msg: %s", method, inner.Code, inner.Msg)
		}
		if inner.Data.ErrorCode != "0" {
			msg := inner.Data.ErrorMsg
			if msg == "" {
				msg = fmt.Sprintf("errorCode %s", inner.Data.ErrorCode)
			}
			return fmt.Errorf("%s failed: %s", method, msg)
		}
		raw = inner.Data.Data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
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
// 鉴权失效时自动恢复会话并重试一次。
func (d *ZhiJiaDisk) getToken(ctx context.Context, pathFileName string, uploadType int) (string, error) {
	var token string
	err := d.withRelogin(ctx, func() error {
		t, err := d.fetchToken(ctx, pathFileName, uploadType)
		if err != nil {
			return err
		}
		token = t
		return nil
	})
	if err != nil {
		return "", err
	}
	// 换 token 的响应可能刷新 cookie，落库
	if d.saveCookies() {
		op.MustSaveDriverStorage(d)
	}
	return token, nil
}

func (d *ZhiJiaDisk) fetchToken(ctx context.Context, pathFileName string, uploadType int) (string, error) {
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
