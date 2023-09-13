package networker

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	ecies "github.com/ecies/go/v2"
)

type EccTcpClient struct {
	PackagedTcpClient
	EncryptKey   []byte
	Ecc          *ECC
	PubKey       *ecies.PublicKey
	onEccPackage func(tcp *EccTcpClient, pkg *EccPackage)
}

func NewEccTcpClient() *EccTcpClient {
	tcp := EccTcpClient{PackagedTcpClient: *NewClient(nil)}
	tcp.initVar()
	return &tcp
}

func NewEccTcpClientWithConn(conn *net.Conn) *EccTcpClient {
	tcp := EccTcpClient{PackagedTcpClient: *NewClient(conn)}
	tcp.initVar()
	return &tcp
}

func (tcp *EccTcpClient) SetEccPackageHandler(handler func(tcp *EccTcpClient, pkg *EccPackage)) {
	if nil == handler {
		tcp.OnOnePackage = nil
		tcp.onEccPackage = nil
	} else {
		tcp.OnOnePackage = tcp.onePackageHandler
		tcp.onEccPackage = handler
	}
}

func (tcp *EccTcpClient) initVar() {
	if nil == tcp.Ecc {
		tcp.Ecc = &ECC{}
		tcp.Ecc.initKey()
	}
}

func (tcp *EccTcpClient) onePackageHandler(client *PackagedTcpClient, pacSN uint16, data []byte) {
	tcp.onOneEccPackage(tcp.pkg2EccPkg(pacSN, data))
}

func (tcp *EccTcpClient) onOneEccPackage(pkg *EccPackage) {
	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		var cmd EccCmd
		err := json.Unmarshal([]byte(pkg.Json), &cmd)
		if nil != err {
			fmt.Println("EccTcpClient.onOneEccPackage json转对象异常", err)
		} else {
			switch cmd.Cmd {
			case 1, 2:
				tcp.onAuthorizeCmd(pkg.PacSN, &cmd)
			}
		}
	}

	if nil == tcp.onEccPackage {
		return
	}

	tcp.onEccPackage(tcp, pkg)
}

func (tcp *EccTcpClient) pkg2EccPkg(pacSN uint16, data []byte) *EccPackage {
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

func (tcp *EccTcpClient) Pac2Stream(pkg *EccPackage) []byte {
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

func (tcp *EccTcpClient) SendJson(sn uint16, json string, extData []byte) bool {
	pkg := EccPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	return tcp.Send(sn, tcp.Pac2Stream(&pkg))
}

func (tcp *EccTcpClient) SendJsonJava(sn int, json string, extData []byte) bool {
	return tcp.SendJson(uint16(sn), json, extData)
}

func (tcp *EccTcpClient) SendJsonAndWait(sn uint16, json string, extData []byte, msWait int) *EccPackage {
	pkg := EccPackage{}
	pkg.ExtData = extData
	pkg.Json = json
	pkg.PacSN = sn

	ans := tcp.SendAndWait(sn, tcp.Pac2Stream(&pkg), msWait)
	if nil == ans {
		fmt.Println("EccTcpServer.SendJsonAndWait PacSN=", sn, " 没有收到回复 PacSN=")
		return nil
	}

	jsonLen := (uint16(ans.Data[1]) << 8)
	jsonLen |= uint16(ans.Data[2])

	ansPkg := tcp.pkg2EccPkg(sn, ans.Data)

	return ansPkg
}

func (tcp *EccTcpClient) SendJsonAndWaitJava(sn int, json string, extData []byte, msWait int) *EccPackage {
	return tcp.SendJsonAndWait(uint16(sn), json, extData, msWait)
}

func (tcp *EccTcpClient) ReadEccPackage() *EccPackage {
	return tcp.readEccPackage(0)
}

func (tcp *EccTcpClient) readEccPackage(msTimeOut int) *EccPackage {
	pkg := tcp.PackagedTcpClient.readPackage(msTimeOut)

	if nil == pkg {
		return nil
	}

	fuPkg := tcp.pkg2EccPkg(pkg.PacSN, pkg.Data)

	//非回复包的认证和心跳包处理
	if pkg.PacSN&0x8000 <= 0 {
		var cmd EccCmd
		err := json.Unmarshal([]byte(fuPkg.Json), &cmd)
		if nil != err {
			fmt.Println("EccTcpClient.ReadEccPackage json转对象异常", err)
		} else {
			switch cmd.Cmd {
			case 1, 2:
				tcp.onAuthorizeCmd(fuPkg.PacSN, &cmd)
			}
		}
	}

	return fuPkg
}

func (tcp *EccTcpClient) onAuthorizeCmd(pacSN uint16, cmd *EccCmd) {
	tcp.initVar()

	var newKey []byte
	newKey = nil

	rslt := EccCmd{}
	rslt.Cmd = cmd.Cmd

	switch cmd.Cmd {
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

	tcp.SendJson(0x8000|pacSN, string(jstr), nil)

	if nil != newKey {
		tcp.EncryptKey = newKey
	}
}

// 封装身份验证操作
func (tcp *EccTcpClient) Login(host string, port int, username string, pwd string, msTimeOut int) bool {
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
		pac := tcp.readEccPackage(msTimeOut)
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

var OnAuthorize func(name string, pwd string) bool

func AuthorizeConn(conn *net.Conn) *EccTcpClient {
	var name, password string

	ptc := NewEccTcpClientWithConn(conn)
	fmt.Println("Received client:", (*conn).RemoteAddr())
	ptc.StartWaitLoop()

	cmd := EccCmd{IsOK: true}
	cmd.Cmd = 1
	cmd.Data = ptc.Ecc.EccKey.PublicKey.Hex(true)
	jdata, _ := json.Marshal(cmd)
	pkg := ptc.SendJsonAndWait(GetNexPacSN(), string(jdata), nil, 3000)
	if nil == pkg {
		fmt.Println("Failed to request public key")
		ptc.Close()
		return nil
	}

	fmt.Println("Received:", pkg.Json)
	var cmdRslt EccCmd
	err := json.Unmarshal([]byte(pkg.Json), &cmdRslt)
	if nil != err {
		fmt.Println("Failed to convert package to command", err)
		ptc.Close()
		return nil
	}

	key, err := ecies.NewPublicKeyFromHex(cmdRslt.Data.(string))
	if nil != err {
		fmt.Println("Failed to convert public key", err)
		ptc.Close()
		return nil
	}

	ptc.PubKey = key
	fmt.Println("Public Key:", ptc.PubKey.Hex(true))

	cmd.Cmd = Cmd_GetPrivateKey
	cmd.Data = time.Now().Unix()
	jdata, _ = json.Marshal(cmd)
	pkg = ptc.SendJsonAndWait(GetNexPacSN(), string(jdata), nil, 3000)
	if nil == pkg {
		fmt.Println("failed to request private key")
		ptc.Close()
		return nil
	}

	fmt.Println("Received: ", pkg.Json)
	err = json.Unmarshal([]byte(pkg.Json), &cmdRslt)
	if nil != err {
		fmt.Println("Failed to convert package to command", err)
		ptc.Close()
		return nil
	}
	if nil == cmdRslt.Data {
		fmt.Println("Empty private key", err)
		ptc.Close()
		return nil
	}
	tmpKey, err := hex.DecodeString(cmdRslt.Data.(string))
	if nil != err {
		fmt.Println("Failed to convert private key", err)
		ptc.Close()
		return nil
	}
	ptc.EncryptKey = tmpKey

	rslt := EccCmd{IsOK: false}
	rslt.Cmd = Cmd_AuthorizeResult
	for idx := 0; idx < 1; idx++ {
		//请求用户名密码
		cmd.Cmd = Cmd_GetUserNamePwd
		cmd.Data = time.Now().Unix()
		jdata, _ = json.Marshal(cmd)
		pkg = ptc.SendJsonAndWait(GetNexPacSN(), string(jdata), nil, 3000)
		if nil == pkg {
			fmt.Println("Failed to request name and password")
			ptc.Close()
			return nil
		}

		fmt.Println("Received: ", pkg.Json)
		err = json.Unmarshal([]byte(pkg.Json), &cmdRslt)
		if nil != err {
			fmt.Println("Failed to convert package to command", err)
			ptc.Close()
			return nil
		}

		if nil == cmdRslt.Data {
			rslt.IsOK = false
			rslt.Msg = "Empty data field"
			break
		}

		dic, ok := cmdRslt.Data.(map[string]any)
		if !ok {
			rslt.IsOK = false
			rslt.Msg = "Data field is not an object"
			break
		}
		obj, has := dic["name"]
		if !has {
			rslt.IsOK = false
			rslt.Msg = "No name field"
			break
		}
		if nil == obj || len(obj.(string)) <= 0 {
			rslt.IsOK = false
			rslt.Msg = "Empty name"
			break
		}
		name = obj.(string)
		obj, has = dic["pwd"]
		if !has {
			rslt.IsOK = false
			rslt.Msg = "No password field"
			break
		}
		password = obj.(string)

		//Check UserName and Password here
		if nil == OnAuthorize || !OnAuthorize(name, password) {
			rslt.IsOK = false
			rslt.Msg = "name or password is not correct"
			break
		}

		rslt.IsOK = true
	}

	//发送认证结果
	jdata, _ = json.Marshal(rslt)
	ptc.SendJson(GetNexPacSN(), string(jdata), nil)

	if rslt.IsOK {
		ptc.User = &LoginUserInfo{ID: 0, Name: name}
		fmt.Println("Authorize OK")
		return ptc
	} else {
		fmt.Println("Failed to authorize:", rslt.Msg)
		ptc.Close()
		return nil
	}
}
