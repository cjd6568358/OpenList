package itvsh

import (
	"encoding/json"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// apiResp 是所有 /nas/* 接口的通用信封。
// data 的类型随接口而变（密钥/token 是字符串，登录信息是对象），故延迟解析。
type apiResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// nasResp 是 nasProxy（POST /nas/rd_center/data/get）的信封。
// 业务错误码在 data.errorCode（字符串），"0" 表示成功。
type nasResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		ErrorCode string          `json:"errorCode"`
		ErrorMsg  string          `json:"errorMsg"`
		Data      json.RawMessage `json:"data"`
	} `json:"data"`
}

// fileEntry 是列表接口返回的文件/目录条目。
// 服务端不返回 id，id 需在客户端拼成 path + "/" + filename。
type fileEntry struct {
	Path     string `json:"path"`     // 父目录，如 "/" 或 "/来自：手机备份"
	Filename string `json:"filename"` // 节点名
	Type     string `json:"type"`     // "DIR" 目录 / "REG" 文件
	Size     string `json:"size"`     // 字节数，字符串形式
	Mtime    string `json:"mtime"`    // 秒级时间戳，字符串形式
	Ctime    string `json:"ctime"`
	Atime    string `json:"atime"`
	Offset   string `json:"offset"` // 分页游标（本驱动不分页，仅保留字段）
}

// obj 把 API 条目转成 OpenList 的 model.Obj。
// ID 与 Path 都取完整路径——本驱动的文件标识就是路径本身。
// 路径会做 homeshare 归一化：部分账号返回的「家庭共享」目录，真实路径是 /homeshare。
func (f *fileEntry) obj() model.Obj {
	full := normalizePath(joinPath(f.Path, f.Filename))
	return &model.Object{
		ID:       full,
		Path:     full,
		Name:     f.Filename,
		Size:     parseInt64(f.Size),
		Modified: parseTime(f.Mtime),
		Ctime:    parseTime(f.Ctime),
		IsFolder: f.Type == "DIR",
	}
}

// loginData 是 /nas/user/login 与 /nas/user/info 的 data 字段
type loginData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Mobile       string `json:"mobile"`
	Expire       string `json:"expire"`
	ForwardUrl   string `json:"forwardUrl"`
}

// volumeInfo 是 /nas/volume/info 的 data 字段
type volumeInfo struct {
	Capacity     int64  `json:"capacity"`
	CapacityUsed int64  `json:"capacityUsed"`
	Size         int64  `json:"size"`
	UserSize     int64  `json:"userSize"`
	Status       string `json:"status"`
	VolumeName   string `json:"volumeName"`
}
