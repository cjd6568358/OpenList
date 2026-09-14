package zhijiadisk

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	Mobile      string `json:"mobile" required:"true" help:"手机号（智家硬盘/天翼云盘账号）"`
	Password    string `json:"password" required:"true" help:"登录密码，会用服务端下发的密钥做 AES 加密后提交"`
	AccessToken string `json:"access_token" help:"可留空。填入后跳过账号密码登录"`
	driver.RootPath
	UploadThread int `json:"upload_thread" type:"number" default:"3" help:"并发分块上传数，1-8"`

	// ForwardUrl 由登录/用户信息接口返回，上传下载走这个域名。
	// 故意不带 json tag：getAdditionalItems 会跳过无 tag 字段，
	// 这样它不会出现在添加存储的表单里，但仍会被持久化。
	ForwardUrl string
}

var config = driver.Config{
	Name:        "ZhiJiaDisk",
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
