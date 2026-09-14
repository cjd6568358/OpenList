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
