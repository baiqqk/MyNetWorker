/*

MIT License

Copyright (c) 2025 baiqqk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

package networker

import (
	"fmt"

	ecies "github.com/ecies/go/v2"
)

type AesPackage struct {
	PacSN       uint16
	Cmd         uint16
	IsEncrypted bool
	Json        string
	ExtData     []byte
}

func (pkg *AesPackage) ToAesStream(aesKey []byte) []byte {
	//包格式：1字节标识位 + 2字节Json长度(小端结尾) + Json数据 + ExtData

	jsonData := []byte(pkg.Json)
	jsonLen := 0
	if nil != jsonData {
		jsonLen = len(jsonData)
	}

	flag := make([]byte, 3)
	if pkg.IsEncrypted {
		flag[0] = 1
		enData, err := RandomEncrypt(jsonData, aesKey)
		if nil != err {
			fmt.Println("FurisonPackage.ToAesStream 加密Json异常", err)
			return nil
		}

		jsonData = enData
		jsonLen = len(jsonData)
	} else {
		flag[0] = 0
	}
	flag[1] = byte(jsonLen >> 8)
	flag[2] = byte(jsonLen)

	return bytesCombine2(flag, jsonData, pkg.ExtData)
}

func (pkg *AesPackage) ToEccStream(eccKey *ecies.PublicKey) []byte {
	//包格式：1字节标识位 + 2字节Json长度(小端结尾) + Json数据 + ExtData

	jsonData := []byte(pkg.Json)
	jsonLen := 0
	if nil != jsonData {
		jsonLen = len(jsonData)
	}

	flag := make([]byte, 3)
	if pkg.IsEncrypted {
		flag[0] = 1
		enData, err := ecies.Encrypt(eccKey, jsonData)
		if nil != err {
			fmt.Println("FurisonPackage.ToEccStream 加密Json异常", err)
			return nil
		}

		jsonData = enData
		jsonLen = len(jsonData)
	} else {
		flag[0] = 0
	}
	flag[1] = byte(jsonLen >> 8)
	flag[2] = byte(jsonLen)

	return bytesCombine2(flag, jsonData, pkg.ExtData)
}

func (pac *AesPackage) SetPacSN(val int) {
	pac.PacSN = uint16(val)
}

func (pac *AesPackage) GetPacSN() int {
	return int(pac.PacSN)
}
