package itvsh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/errgroup"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/avast/retry-go"
)

// upload 实现分块并发上传。
//
// 流程（与小程序/web 版一致）：
//  1. 换上传 token（uploadType=0）
//  2. 分块并发 POST 到 {forwardUrl}/nasforward/file/binary/upload，
//     每块的 fileName 参数是「原名 + .crash」，offset 为该块起始位置
//  3. 全部传完后收尾：exist 检查同名 -> 有则先删 -> 把 .crash 改名回真名
func (d *Itvsh) upload(ctx context.Context, dstDir model.Obj, file model.FileStreamer, up driver.UpdateProgress) error {
	dir := normalizePath(dstDir.GetPath())
	name := file.GetName()
	fullPath := joinPath(dir, name)

	// 上传前先清掉可能残留的 .crash（上次中断留下的）
	_, _ = d.nasProxy(ctx, methodDeleteFile, base.Json{
		"directory": dir,
		"filename":  name + ".crash",
	})

	token, err := d.getToken(ctx, fullPath, uploadTypeUpload)
	if err != nil {
		return err
	}

	size := file.GetSize()
	uploadUrl := d.forwardUrl() + pathPutFile

	// 全量流需缓存后才能随机分段读取；有 File 时是零拷贝分段
	ss, err := stream.NewStreamSectionReader(file, chunkSize, &up)
	if err != nil {
		return err
	}

	chunks := (size + chunkSize - 1) / chunkSize
	if chunks <= 0 {
		chunks = 1
	}
	thread := min(int(chunks), d.UploadThread)

	// 取消时清理残留的 .crash，避免留下垃圾文件
	defer func() {
		if utils.IsCanceled(ctx) {
			_, _ = d.nasProxy(context.Background(), methodDeleteFile, base.Json{
				"directory": dir,
				"filename":  name + ".crash",
			})
		}
	}()

	threadG, uploadCtx := errgroup.NewOrderedGroupWithContext(ctx, thread,
		retry.Attempts(3),
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay))

	for i := range chunks {
		if utils.IsCanceled(uploadCtx) {
			break
		}
		index := i
		offset := int64(index) * chunkSize
		length := min(int64(chunkSize), size-offset)

		threadG.GoWithLifecycle(errgroup.Lifecycle{
			Do: func(ctx context.Context) error {
				if utils.IsCanceled(ctx) {
					return ctx.Err()
				}
				// 鉴权失效时刷新会话再重传这一块。
				// 下面这段会整体重跑，所以 body 必须在每次尝试时重新申请，
				// 否则第二次尝试会读到已耗尽的 reader。
				err := d.withRelogin(ctx, func() error {
					reader, err := ss.GetSectionReader(offset, length)
					if err != nil {
						return err
					}
					defer ss.FreeSectionReader(reader)

					body, err := io.ReadAll(reader)
					if err != nil {
						return err
					}
					if int64(len(body)) != length {
						return fmt.Errorf("chunk %d: short read, want %d got %d", index, length, len(body))
					}

					q := url.Values{}
					q.Set("uploadToken", token)
					q.Set("fileName", name+".crash")
					q.Set("directory", dir)
					q.Set("offset", strconv.FormatInt(offset, 10))
					reqUrl := uploadUrl + "?" + q.Encode()

					req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqUrl, bytes.NewReader(body))
					if err != nil {
						return err
					}
					for k, v := range d.authHeaders() {
						req.Header.Set(k, v)
					}
					req.Header.Set("Content-Type", "application/octet-stream")
					// base.HttpClient 不设 UA，Go 默认会补 Go-http-client/1.1。
					// 上游 WAF 对头部敏感（见 Init 注释），显式清空对齐 Web 版。
					req.Header.Set("User-Agent", "")
					// base.HttpClient 也不认我们的 cookie jar，手动补上 WAF 挑战 cookie
					if ck := d.cookieHeader(reqUrl); ck != "" {
						req.Header.Set("Cookie", ck)
					}
					req.ContentLength = length
					// 走限速 reader；ContentLength 已显式设置，
					// 否则 Go 无法为这种非 bytes/strings reader 推断长度
					req.Body = driver.NewLimitedUploadStream(ctx, bytes.NewReader(body))

					res, err := base.HttpClient.Do(req)
					if err != nil {
						return err
					}
					defer res.Body.Close()
					// 把响应里的 set-cookie 收进 jar：WAF 首次挑战成功后会在这里种
					// 挑战 cookie，后续的 resty 请求就能自动带上（对照 proxy-server.js:79）
					if u, perr := url.Parse(reqUrl); perr == nil && len(res.Cookies()) > 0 {
						d.jar.SetCookies(u, res.Cookies())
					}
					respBody, _ := io.ReadAll(res.Body)
					if res.StatusCode != 200 {
						if res.StatusCode == http.StatusPreconditionFailed {
							return fmt.Errorf("chunk %d: 被上游 WAF 拦截 (HTTP 412)，请检查请求头配置", index)
						}
						return fmt.Errorf("chunk %d upload failed: HTTP %d, body: %s",
							index, res.StatusCode, string(respBody))
					}
					// 成功判断：code==200 且内层 result=="successful"
					if err := checkChunkResult(respBody); err != nil {
						return fmt.Errorf("chunk %d: %w", index, err)
					}
					return nil
				})
				return err
			},
		})
	}

	if err := threadG.Wait(); err != nil {
		return err
	}
	if utils.IsCanceled(ctx) {
		return ctx.Err()
	}

	// 上传过程中收到的 set-cookie（含 WAF 挑战 cookie）落库，重启后仍可复用
	if d.saveCookies() {
		op.MustSaveDriverStorage(d)
	}

	return d.finalizeUpload(ctx, dir, name)
}

// finalizeUpload 收尾：把「文件名.crash」变成正式文件。
// 若已存在同名文件，需先删除，否则重命名会失败。
func (d *Itvsh) finalizeUpload(ctx context.Context, dir, name string) error {
	exists, err := d.fileExist(ctx, dir, name)
	if err != nil {
		return err
	}
	if exists {
		if _, err := d.nasProxy(ctx, methodDeleteFile, base.Json{
			"directory": dir,
			"filename":  name,
		}); err != nil {
			return fmt.Errorf("delete existing file failed: %w", err)
		}
	}
	_, err = d.nasProxy(ctx, methodFileRename, base.Json{
		"directory":   dir,
		"filename":    name + ".crash",
		"newFilename": name,
	})
	return err
}

// checkChunkResult 解析分块上传响应。
// 形如 {"code":200,"data":"{\"result\":\"successful\"}"}，data 可能是
// JSON 字符串也可能已是对象，故两种都处理。
func checkChunkResult(body []byte) error {
	var resp struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := utils.Json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parse upload response failed: %w, body: %s", err, string(body))
	}
	if resp.Code != 200 {
		return fmt.Errorf("upload failed: code %d, body: %s", resp.Code, string(body))
	}
	// data 可能是被转义的 JSON 字符串，先尝试解成对象
	var inner struct {
		Result  string `json:"result"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := utils.Json.Unmarshal(resp.Data, &inner); err != nil {
		var s string
		if err2 := utils.Json.Unmarshal(resp.Data, &s); err2 != nil {
			return fmt.Errorf("parse upload data failed: %w", err)
		}
		if err3 := utils.Json.Unmarshal([]byte(s), &inner); err3 != nil {
			return fmt.Errorf("parse upload data string failed: %w", err3)
		}
	}
	if inner.Result == "successful" {
		return nil
	}
	// 1009 表示 token 失效，交由上层重试
	if inner.Code == 1009 {
		return fmt.Errorf("upload token invalid (1009)")
	}
	msg := inner.Message
	if msg == "" {
		msg = "unknown error"
	}
	return fmt.Errorf("upload failed: %s", msg)
}
