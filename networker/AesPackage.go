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
)

type AesPackage struct {
	PacSN   uint16
	Cmd     uint16
	Json    string
	ExtData []byte
}

func (pkg *AesPackage) ToAesStream(aesKey []byte) []byte {
	//包格式：2字节(cmd+Json)长度(小端结尾) 2字节cmd(小端结尾) + + Json数据 + ExtData

	buf := []byte{byte(pkg.Cmd >> 8), byte(pkg.Cmd)}
	buf = append(buf, []byte(pkg.Json)...)

	if len(aesKey) > 0 {
		enc, err := RandomEncrypt(buf, aesKey)
		if nil != err {
			fmt.Println("FurisonPackage.ToAesStream 加密Json异常", err)
			return nil
		}

		buf = enc
	}

	bufLen := len(buf)

	flag := make([]byte, 2)
	flag[0] = byte(bufLen >> 8)
	flag[1] = byte(bufLen)

	flag = append(flag, buf...)
	flag = append(flag, pkg.ExtData...)

	return flag
}

func (pac *AesPackage) SetPacSN(val int) {
	pac.PacSN = uint16(val)
}

func (pac *AesPackage) GetPacSN() int {
	return int(pac.PacSN)
}
