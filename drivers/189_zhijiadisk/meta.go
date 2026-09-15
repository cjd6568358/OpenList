package zhijiadisk

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	// Mobile/Password 与 AccessToken 是「二选一」关系，所以两者都不标 required ——
	// required 会让前端在提交前直接拦下，用不了 AccessToken 单独登录。
	// 参照 115 Cloud 的做法：把约束写进 help 文案，真正的校验交给 Init()。
	Mobile      string `json:"mobile" help:"手机号（智家硬盘/天翼云盘账号），与 Access token 二选一"`
	Password    string `json:"password" help:"登录密码，会用服务端下发的密钥做 AES 加密后提交，与 Access token 二选一"`
	AccessToken string `json:"access_token" help:"可留空，与手机号+密码二选一。填入后跳过账号密码登录"`
	driver.RootPath
	// 默认 5，与官方小程序 / web 客户端的 maxConcurrency 对齐
	UploadThread int `json:"upload_thread" type:"number" default:"5" help:"并发分块上传数，1-8"`

	// ForwardUrl 由登录/用户信息接口返回，上传下载走这个域名。
	// 故意不带 json tag：getAdditionalItems 会跳过无 tag 字段，
	// 这样它不会出现在添加存储的表单里，但仍会被持久化。
	ForwardUrl string

	// Cookies 持久化上游下发的会话 cookie（JSON 数组）。
	// 同上，不带 json tag，不进表单。
	// 登录态实际靠 cookie 维持（token 失效时可凭 cookie 不带密码重取用户信息），
	// 只放在内存 jar 里一重启就丢，会导致反复要求用户重新登录。
	Cookies string
}

var config = driver.Config{
	// 显示在「添加存储」的驱动下拉框里。
	// 注意这也是持久化到 Storage.Driver 的值，改名会让已配置的存储
	// 在启动时报 "no driver named: ..."，需要删除后重新添加。
	Name:        "上海电信智家硬盘",
	DefaultRoot: "/",
	// Link 返回的是需要带 X-NAS-SDKTOKEN 头的地址，浏览器直连拿不到，
	// 上游还会校验，因此强制走代理。
	OnlyProxy: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &ZhiJiaDisk{}
	})
}
