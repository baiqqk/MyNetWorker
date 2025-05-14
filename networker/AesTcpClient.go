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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"

	ecies "github.com/ecies/go/v2"
)

type AesTcpClient struct {
	PackagedTcpClient
	aesKey       []byte
	onAesPackage func(tcp *AesTcpClient, pkg *AesPackage)
}

func NewAesTcpClient() *AesTcpClient {
	tcp := AesTcpClient{PackagedTcpClient: *NewClient(nil)}
	return &tcp
}

func NewAesTcpClientWithConn(conn *net.Conn) *AesTcpClient {
	tcp := AesTcpClient{PackagedTcpClient: *NewClient(conn)}
	return &tcp
}

func (tcp *AesTcpClient) SetAesPackageHandler(handler func(tcp *AesTcpClient, pkg *AesPackage)) {
	if nil == handler {
		tcp.OnOnePackage = nil
		tcp.onAesPackage = nil
	} else {
		tcp.OnOnePackage = tcp.onePackageHandler
		tcp.onAesPackage = handler
	}
}

func (tcp *AesTcpClient) onePackageHandler(client *PackagedTcpClient, pacSN uint16, data []byte) {
	tcp.onOneAesPackage(tcp.pkg2AesPkg(pacSN, data))
}

func (tcp *AesTcpClient) onOneAesPackage(pkg *AesPackage) {
	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		switch pkg.Cmd {
		case Cmd_GetAesKey:
			var cmd AesCmd
			err := json.Unmarshal([]byte(pkg.Json), &cmd)
			if nil != err {
				fmt.Println("AesTcpClient.onOneAesPackage json转对象异常", err)
			} else {
				tcp.onAuthorizeCmd(pkg.PacSN, pkg.Cmd, &cmd)
			}

			return
		}
	}

	if nil == tcp.onAesPackage {
		return
	}

	tcp.onAesPackage(tcp, pkg)
}

func (tcp *AesTcpClient) pkg2AesPkg(pacSN uint16, data []byte) *AesPackage {
	var err error
	var deData []byte

	jsonLen := (uint16(data[0]) << 8)
	jsonLen |= uint16(data[1])

	ansPkg := AesPackage{}
	ansPkg.PacSN = pacSN
	ansPkg.ExtData = data[2+jsonLen:]

	// if nil == tcp.AesKey && nil == tcp.Ecc {
	// 	fmt.Println("AesTcpClient.pkg2AesPkg PacSN=", pacSN, " 解密信息包失败：密钥为空 ")
	// 	return nil
	// }

	if jsonLen > 0 {
		if nil != tcp.aesKey {
			deData, err = RandomDecrypt(data[2:jsonLen+2], tcp.aesKey)
			if nil != err {
				fmt.Println("AesTcpClient.pkg2AesPkg PacSN=", pacSN, " 解密信息包失败：", err)
				return nil
			}
		} else {
			deData = data[2 : jsonLen+2]
		}

		// fmt.Println(tcp.ClientFlag, "解密数据:", hex.EncodeToString(data[2:jsonLen+2]), " 解密后:", hex.EncodeToString(deData))

		ansPkg.Cmd = (uint16(deData[0]) << 8) | uint16(deData[1])
		ansPkg.Json = string(deData[2:])
	}

	return &ansPkg
}

func (tcp *AesTcpClient) SendJson(sn uint16, cmd uint16, json string, extData []byte) bool {
	pkg := AesPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn
	pkg.Cmd = cmd

	return tcp.Send(sn, pkg.ToAesStream(tcp.aesKey))
}

func (tcp *AesTcpClient) SendJsonJava(sn int, cmd int, json string, extData []byte) bool {
	return tcp.SendJson(uint16(sn), uint16(cmd), json, extData)
}

func (tcp *AesTcpClient) SendJsonAndWait(sn uint16, cmd uint16, json string, extData []byte, msWait int) *AesPackage {
	pkg := AesPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn
	pkg.Cmd = cmd

	ans := tcp.SendAndWait(sn, pkg.ToAesStream(tcp.aesKey), msWait)
	if nil == ans {
		fmt.Println("AesTcpClient.SendJsonAndWait PacSN=", sn, " 没有收到回复 PacSN=")
		return nil
	}

	jsonLen := (uint16(ans.Data[1]) << 8)
	jsonLen |= uint16(ans.Data[2])

	ansPkg := tcp.pkg2AesPkg(sn, ans.Data)

	return ansPkg
}

func (tcp *AesTcpClient) SendJsonAndWaitJava(sn int, cmd int, json string, extData []byte, msWait int) *AesPackage {
	return tcp.SendJsonAndWait(uint16(sn), uint16(cmd), json, extData, msWait)
}

func (tcp *AesTcpClient) ReadAesPackage() *AesPackage {
	return tcp.readAesPackage(0)
}

func (tcp *AesTcpClient) readAesPackage(msTimeOut int) *AesPackage {
	pkg := tcp.PackagedTcpClient.readPackage(msTimeOut)

	if nil == pkg {
		return nil
	}

	aesPkg := tcp.pkg2AesPkg(pkg.PacSN, pkg.Data)
	if nil == aesPkg {
		return nil
	}

	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		switch aesPkg.Cmd {
		case Cmd_GetAesKey:
			var cmd AesCmd
			err := json.Unmarshal([]byte(aesPkg.Json), &cmd)
			if nil != err {
				fmt.Println("AesTcpClient.pkg2AesPkg json转对象异常", err)
			} else {
				tcp.onAuthorizeCmd(aesPkg.PacSN, aesPkg.Cmd, &cmd)
			}
		}
	}

	return aesPkg
}

func (tcp *AesTcpClient) onAuthorizeCmd(pacSN uint16, cmdType uint16, cmd *AesCmd) {
	var newKey []byte

	newKey = nil
	ecc := ECC{}
	ecc.initKey()

	rslt := AesCmd{}

	switch cmdType {
	case Cmd_GetAesKey:
		{
			if nil == cmd.Data || len(cmd.Data.(string)) <= 0 {
				fmt.Println("AesTcpClient.onAuthorizeCmd 空公钥")
				rslt.IsOK = false
				rslt.Msg = "Empty PubKey"
			} else {
				bs := cmd.Data.(string)
				key, err := ecies.NewPublicKeyFromHex(bs)
				if nil != err {
					fmt.Println("AesTcpClient.onAuthorizeCmd 数据转公钥异常", err)
					rslt.IsOK = false
					rslt.Msg = err.Error()
				} else {
					newKey = newAesKey()
					rslt.IsOK = true
					rslt.Data = hex.EncodeToString(ecc.Encrypt(newKey, key))
				}
			}
		}
	}

	jstr, err := json.Marshal(rslt)
	if nil != err {
		fmt.Println("AesTcpClient.onAuthorizeCmd 结果转JSON异常", err)
		return
	}

	tcp.SendJson(0x8000|pacSN, cmdType, string(jstr), nil)

	if nil != newKey {
		tcp.aesKey = newKey
	}
}
