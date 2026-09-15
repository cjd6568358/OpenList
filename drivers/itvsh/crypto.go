package itvsh

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
)

// aesEncodeHex 用 AES-ECB/Pkcs7 加密并返回十六进制字符串。
//
// 对应小程序 utils/AES.js 的 AES_encode：
//   - key 按 Utf8 解析（ASCII 字符即其字节本身，实测密钥为 16 字符 -> AES-128）
//   - 输出**小写** hex（注意 189pc 的同名函数是大写，两者不可混用）
func aesEncodeHex(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), block.BlockSize())
	out := make([]byte, len(padded))
	size := block.BlockSize()
	for src, dst := padded, out; len(src) > 0; src, dst = src[size:], dst[size:] {
		block.Encrypt(dst[:size], src[:size])
	}
	return hex.EncodeToString(out), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding <= 0 || padding > blockSize {
		padding = blockSize
	}
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}
