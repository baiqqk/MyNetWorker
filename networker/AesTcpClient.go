/*

MIT License

Copyright (c) 2023 baiqqk

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
	"time"

	ecies "github.com/ecies/go/v2"
)

type AesTcpClient struct {
	PackagedTcpClient
	EncryptKey   []byte
	Ecc          *ECC
	PubKey       *ecies.PublicKey
	onAesPackage func(tcp *AesTcpClient, pkg *AesPackage)
}

func NewAesTcpClient() *AesTcpClient {
	tcp := AesTcpClient{PackagedTcpClient: *NewClient(nil)}
	tcp.initVar()
	return &tcp
}

func NewAesTcpClientWithConn(conn *net.Conn) *AesTcpClient {
	tcp := AesTcpClient{PackagedTcpClient: *NewClient(conn)}
	tcp.initVar()
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

func (tcp *AesTcpClient) initVar() {
	if nil == tcp.Ecc {
		tcp.Ecc = &ECC{}
		tcp.Ecc.initKey()
	}
}

func (tcp *AesTcpClient) onePackageHandler(client *PackagedTcpClient, pacSN uint16, cmd uint16, data []byte) {
	tcp.onOneAesPackage(tcp.pkg2AesPkg(pacSN, cmd, data))
}

func (tcp *AesTcpClient) onOneAesPackage(pkg *AesPackage) {
	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		switch pkg.Cmd {
		case Cmd_GetPubKey, Cmd_GetPrivateKey:
			var cmd AesCmd
			err := json.Unmarshal([]byte(pkg.Json), &cmd)
			if nil != err {
				fmt.Println("EccTcpClient.onOneEccPackage json转对象异常", err)
			} else {
				tcp.onAuthorizeCmd(pkg.PacSN, pkg.Cmd, &cmd)
			}
		}
	}

	if nil == tcp.onAesPackage {
		return
	}

	tcp.onAesPackage(tcp, pkg)
}

func (tcp *AesTcpClient) pkg2AesPkg(pacSN uint16, cmd uint16, data []byte) *AesPackage {
	jsonLen := (uint16(data[1]) << 8)
	jsonLen |= uint16(data[2])

	ansPkg := AesPackage{}
	ansPkg.PacSN = pacSN
	ansPkg.Cmd = cmd
	ansPkg.IsEncrypted = (0x01 & data[0]) > 0
	ansPkg.ExtData = data[3+jsonLen:]

	if !ansPkg.IsEncrypted {
		ansPkg.Json = string(data[3 : jsonLen+3])
	} else {
		tcp.initVar()

		if nil == tcp.EncryptKey && nil == tcp.Ecc {
			fmt.Println("EccTcpServer.pkg2EccPkg PacSN=", pacSN, " 解密信息包失败：密钥为空 ")
			return nil
		}

		if jsonLen > 0 {
			var err error
			var deData []byte
			if nil != tcp.EncryptKey {
				deData, err = RandomDecrypt(data[3:jsonLen+3], tcp.EncryptKey)
				if nil != err {
					fmt.Println("EccTcpServer.pkg2EccPkg PacSN=", pacSN, " 解密信息包失败：", err)
					return nil
				}
			} else if nil != tcp.Ecc {
				deData = tcp.Ecc.Decrypt(data[3 : jsonLen+3])
				if nil == deData {
					return nil
				}
			} else {
				fmt.Println("EccTcpServer.pkg2EccPkg PacSN=", pacSN, " 解密信息包失败：没有密钥")
				return nil
			}

			ansPkg.Json = string(deData)
		}
	}

	return &ansPkg
}

func (tcp *AesTcpClient) Pac2Stream(pkg *AesPackage) []byte {
	var data []byte
	pkg.IsEncrypted = false
	if nil != tcp.EncryptKey {
		pkg.IsEncrypted = nil != tcp.EncryptKey
		data = pkg.ToAesStream(tcp.EncryptKey)
	} else if nil != tcp.PubKey {
		pkg.IsEncrypted = nil != tcp.PubKey
		data = pkg.ToEccStream(tcp.PubKey)
	} else {
		pkg.IsEncrypted = false
		data = pkg.ToAesStream(nil)
	}

	return data
}

func (tcp *AesTcpClient) SendJson(sn uint16, cmd uint16, json string, extData []byte) bool {
	pkg := AesPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	return tcp.Send(sn, cmd, tcp.Pac2Stream(&pkg))
}

func (tcp *AesTcpClient) SendJsonJava(sn int, cmd int, json string, extData []byte) bool {
	return tcp.SendJson(uint16(sn), uint16(cmd), json, extData)
}

func (tcp *AesTcpClient) SendJsonAndWait(sn uint16, cmd uint16, json string, extData []byte, msWait int) *AesPackage {
	pkg := AesPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	ans := tcp.SendAndWait(sn, cmd, tcp.Pac2Stream(&pkg), msWait)
	if nil == ans {
		fmt.Println("EccTcpServer.SendJsonAndWait PacSN=", sn, " 没有收到回复 PacSN=")
		return nil
	}

	jsonLen := (uint16(ans.Data[1]) << 8)
	jsonLen |= uint16(ans.Data[2])

	ansPkg := tcp.pkg2AesPkg(sn, cmd, ans.Data)

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

	aesPkg := tcp.pkg2AesPkg(pkg.PacSN, pkg.Cmd, pkg.Data)

	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		switch aesPkg.Cmd {
		case Cmd_GetPubKey, Cmd_GetPrivateKey:
			var cmd AesCmd
			err := json.Unmarshal([]byte(aesPkg.Json), &cmd)
			if nil != err {
				fmt.Println("EccTcpClient.ReadEccPackage json转对象异常", err)
			} else {
				tcp.onAuthorizeCmd(aesPkg.PacSN, aesPkg.Cmd, &cmd)
			}
		}
	}

	return aesPkg
}

func (tcp *AesTcpClient) onAuthorizeCmd(pacSN uint16, cmdType uint16, cmd *AesCmd) {
	tcp.initVar()

	var newKey []byte
	newKey = nil

	rslt := AesCmd{}

	switch cmdType {
	case Cmd_GetPubKey:
		{
			if nil == cmd.Data || len(cmd.Data.(string)) <= 0 {
				fmt.Println("EccTcpClient.onAuthorizeCmd 空公钥")
				rslt.IsOK = false
				rslt.Msg = "Empty PubKey"
			} else {
				bs := cmd.Data.(string)
				key, err := ecies.NewPublicKeyFromHex(bs)
				if nil != err {
					fmt.Println("EccTcpClient.onAuthorizeCmd 数据转公钥异常", err)
					rslt.IsOK = false
					rslt.Msg = err.Error()
				} else {
					tcp.PubKey = key
					rslt.IsOK = true
					rslt.Data = tcp.Ecc.EccKey.PublicKey.Hex(true)
				}
			}
		}
	case Cmd_GetPrivateKey:
		{
			if nil != cmd.Data {
				ts := int64(cmd.Data.(float64))
				tm := time.Unix(ts, 0)
				fmt.Println("服务器时间", tm.Format("2006-1-2 15:4:5"))
			}

			rslt.IsOK = true
			rslt.Data = tcp.EncryptKey
			if nil == rslt.Data || len(rslt.Data.([]byte)) <= 0 {
				newKey = getRandomKey()
				rslt.Data = hex.EncodeToString(newKey)
			}
		}
	}

	jstr, err := json.Marshal(rslt)
	if nil != err {
		fmt.Println("EccTcpClient.onAuthorizeCmd 结果转JSON异常", err)
		return
	}

	tcp.SendJson(0x8000|pacSN, cmdType, string(jstr), nil)

	if nil != newKey {
		tcp.EncryptKey = newKey
	}
}
