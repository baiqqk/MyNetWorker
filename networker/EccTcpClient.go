package networker

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	ecies "github.com/ecies/go/v2"
)

type FurisonTcpClient struct {
	PackagedTcpClient
	EncryptKey       []byte
	Ecc              *ECC
	PubKey           *ecies.PublicKey
	onFurisonPackage func(tcp *FurisonTcpClient, pkg *EccPackage)
}

func NewFurisonTcpClient() *FurisonTcpClient {
	tcp := FurisonTcpClient{PackagedTcpClient: *NewClient(nil)}
	tcp.initVar()
	return &tcp
}

func NewFurisonTcpClientWithConn(conn *net.Conn) *FurisonTcpClient {
	tcp := FurisonTcpClient{PackagedTcpClient: *NewClient(conn)}
	tcp.initVar()
	return &tcp
}

func (tcp *FurisonTcpClient) SetFurisonPackageHandler(handler func(tcp *FurisonTcpClient, pkg *EccPackage)) {
	if nil == handler {
		tcp.OnOnePackage = nil
		tcp.onFurisonPackage = nil
	} else {
		tcp.OnOnePackage = tcp.onePackageHandler
		tcp.onFurisonPackage = handler
	}
}

func (tcp *FurisonTcpClient) initVar() {
	if nil == tcp.Ecc {
		tcp.Ecc = &ECC{}
		tcp.Ecc.initKey()
	}
}

func (tcp *FurisonTcpClient) onePackageHandler(client *PackagedTcpClient, pacSN uint16, data []byte) {
	tcp.onOneFurisonPackage(tcp.pkg2FurisonPkg(pacSN, data))
}

func (tcp *FurisonTcpClient) onOneFurisonPackage(pkg *EccPackage) {
	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		var cmd EccCmd
		err := json.Unmarshal([]byte(pkg.Json), &cmd)
		if nil != err {
			fmt.Println("FurisonTcpClient.onOneFurisonPackage json转对象异常", err)
		} else {
			switch cmd.Cmd {
			case 1, 2:
				tcp.onAuthorizeCmd(pkg.PacSN, &cmd)
			}
		}
	}

	if nil == tcp.onFurisonPackage {
		return
	}

	tcp.onFurisonPackage(tcp, pkg)
}

func (tcp *FurisonTcpClient) pkg2FurisonPkg(pacSN uint16, data []byte) *EccPackage {
	jsonLen := (uint16(data[1]) << 8)
	jsonLen |= uint16(data[2])

	ansPkg := EccPackage{}
	ansPkg.PacSN = pacSN
	ansPkg.IsEncrypted = (0x01 & data[0]) > 0
	ansPkg.ExtData = data[3+jsonLen:]

	if !ansPkg.IsEncrypted {
		ansPkg.Json = string(data[3 : jsonLen+3])
	} else {
		tcp.initVar()

		if nil == tcp.EncryptKey && nil == tcp.Ecc {
			fmt.Println("FurisonTcpServer.pkg2FurisonPkg PacSN=", pacSN, " 解密信息包失败：密钥为空 ")
			return nil
		}

		if jsonLen > 0 {
			var err error
			var deData []byte
			if nil != tcp.EncryptKey {
				deData, err = RandomDecrypt(data[3:jsonLen+3], tcp.EncryptKey)
				if nil != err {
					fmt.Println("FurisonTcpServer.pkg2FurisonPkg PacSN=", pacSN, " 解密信息包失败：", err)
					return nil
				}
			} else if nil != tcp.Ecc {
				deData = tcp.Ecc.Decrypt(data[3 : jsonLen+3])
				if nil == deData {
					return nil
				}
			} else {
				fmt.Println("FurisonTcpServer.pkg2FurisonPkg PacSN=", pacSN, " 解密信息包失败：没有密钥")
				return nil
			}

			ansPkg.Json = string(deData)
		}
	}

	return &ansPkg
}

func (tcp *FurisonTcpClient) Pac2Stream(pkg *EccPackage) []byte {
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

func (tcp *FurisonTcpClient) SendJson(sn uint16, json string, extData []byte) bool {
	pkg := EccPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	return tcp.Send(sn, tcp.Pac2Stream(&pkg))
}

func (tcp *FurisonTcpClient) SendJsonJava(sn int, json string, extData []byte) bool {
	return tcp.SendJson(uint16(sn), json, extData)
}

func (tcp *FurisonTcpClient) SendJsonAndWait(sn uint16, json string, extData []byte, msWait int) *EccPackage {
	pkg := EccPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	ans := tcp.SendAndWait(sn, tcp.Pac2Stream(&pkg), msWait)
	if nil == ans {
		fmt.Println("FurisonTcpServer.SendJsonAndWait PacSN=", sn, " 没有收到回复 PacSN=")
		return nil
	}

	jsonLen := (uint16(ans.Data[1]) << 8)
	jsonLen |= uint16(ans.Data[2])

	ansPkg := tcp.pkg2FurisonPkg(sn, ans.Data)

	return ansPkg
}

func (tcp *FurisonTcpClient) SendJsonAndWaitJava(sn int, json string, extData []byte, msWait int) *EccPackage {
	return tcp.SendJsonAndWait(uint16(sn), json, extData, msWait)
}

func (tcp *FurisonTcpClient) ReadFurisonPackage() *EccPackage {
	return tcp.readFurisonPackage(0)
}

func (tcp *FurisonTcpClient) readFurisonPackage(msTimeOut int) *EccPackage {
	pkg := tcp.PackagedTcpClient.readPackage(msTimeOut)

	if nil == pkg {
		return nil
	}

	fuPkg := tcp.pkg2FurisonPkg(pkg.PacSN, pkg.Data)

	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		var cmd EccCmd
		err := json.Unmarshal([]byte(fuPkg.Json), &cmd)
		if nil != err {
			fmt.Println("FurisonTcpClient.ReadFurisonPackage json转对象异常", err)
		} else {
			switch cmd.Cmd {
			case 1, 2:
				tcp.onAuthorizeCmd(fuPkg.PacSN, &cmd)
			}
		}
	}

	return fuPkg
}

func (tcp *FurisonTcpClient) onAuthorizeCmd(pacSN uint16, cmd *EccCmd) {
	tcp.initVar()

	var newKey []byte
	newKey = nil

	rslt := EccCmd{}
	rslt.Cmd = cmd.Cmd

	switch cmd.Cmd {
	case Cmd_GetPubKey:
		{
			if nil == cmd.Data || len(cmd.Data.(string)) <= 0 {
				fmt.Println("FurisonTcpClient.onAuthorizeCmd 空公钥")
				rslt.IsOK = false
				rslt.Msg = "Empty PubKey"
			} else {
				bs := cmd.Data.(string)
				key, err := ecies.NewPublicKeyFromHex(bs)
				if nil != err {
					fmt.Println("FurisonTcpClient.onAuthorizeCmd 数据转公钥异常", err)
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
		fmt.Println("FurisonTcpClient.onAuthorizeCmd 结果转JSON异常", err)
		return
	}

	tcp.SendJson(0x8000|pacSN, string(jstr), nil)

	if nil != newKey {
		tcp.EncryptKey = newKey
	}
}

// 封装身份验证操作
func (tcp *FurisonTcpClient) Login(host string, port int, username string, pwd string, msTimeOut int) bool {
	isOk := false

	defer func() {
		if !isOk {
			tcp.Close()
		}
	}()

	if !tcp.Connect(host, port, msTimeOut) {
		return false
	}

	tcp.StartWaitLoop()

	tmDuration := time.Duration(int64(msTimeOut) * int64(time.Millisecond))
	tmBegin := time.Now()

	for time.Since(tmBegin) < tmDuration {
		pac := tcp.readFurisonPackage(msTimeOut)
		if nil == pac {
			return false
		}

		fmt.Println("接收到数据 PacSN=", pac.PacSN, "Json=", string(pac.Json), "data=", pac.ExtData)
		// client.SendJson()

		cmd := EccCmd{}
		err := json.Unmarshal([]byte(pac.Json), &cmd)
		if nil != err {
			fmt.Println("Json 转 Cmd 失败", err)
			continue
		}

		switch cmd.Cmd {
		case Cmd_GetUserNamePwd:
			{
				ans := EccCmd{}
				ans.Cmd = cmd.Cmd
				ans.IsOK = true
				ans.Msg = ""
				ans.Data = struct {
					Name string `json:"name"`
					Pwd  string `json:"pwd"`
				}{
					Name: username,
					Pwd:  pwd}

				tcp.SendJson(0x8000|pac.PacSN, ans.ToJson(), nil)
			}
		case Cmd_AuthorizeResult:
			{
				if cmd.IsOK {
					isOk = true
					fmt.Println("身份认证成功")
					return isOk
				} else {
					fmt.Println("身份认证失败:", cmd.Msg)
				}
				break
			}
		}
	}

	return false
}
