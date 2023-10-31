package networker

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	ecies "github.com/ecies/go/v2"
)

type TcpListener struct {
	lsener           *net.Listener
	OnClientAccepted func(*net.Conn)
	OnAuthorize      func(name string, pwd string) bool
}

func (lsnr *TcpListener) Start(port int) bool {
	lsnr.Stop()

	lsener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if nil != err {
		fmt.Println("启动监听失败 port=", port, err)
		return false
	}

	lsnr.lsener = &lsener

	go lsnr.acceptLoop()

	return true
}

func (lsnr *TcpListener) Stop() {
	if nil == lsnr.lsener {
		return
	}

	err := (*lsnr.lsener).Close()
	if nil != err {
		fmt.Println("停止监听失败 port=", (*lsnr.lsener).Addr(), err)
	}

	lsnr.lsener = nil
}

func (lsnr *TcpListener) acceptLoop() {
	if nil == lsnr.lsener {
		return
	}

	for nil != lsnr.lsener {
		conn, err := (*lsnr.lsener).Accept()
		if nil != err {
			fmt.Println("接受连接异常", err)
			continue
		}

		if nil != lsnr.OnClientAccepted {
			lsnr.OnClientAccepted(&conn)
		} else {
			fmt.Println("没有请求处理程序，关闭客户端连接", err)
			conn.Close()
		}
	}
}

// 封装身份验证操作
func (tcp *AesTcpClient) Login(host string, port int, username string, pwd string, msTimeOut int) bool {
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
		pac := tcp.readAesPackage(msTimeOut)
		if nil == pac {
			return false
		}

		fmt.Println("接收到数据 PacSN=", pac.PacSN, " Cmd=", pac.Cmd, " Json=", string(pac.Json), " data=", pac.ExtData)
		// client.SendJson()

		switch pac.Cmd {
		case Cmd_GetUserNamePwd:
			{
				ans := AesCmd{}
				ans.IsOK = true
				ans.Msg = ""
				ans.Data = struct {
					Name string `json:"name"`
					Pwd  string `json:"pwd"`
				}{
					Name: username,
					Pwd:  pwd}

				tcp.SendJson(0x8000|pac.PacSN, pac.Cmd, ans.ToJson(), nil)
			}
		case Cmd_AuthorizeResult:
			{
				cmd := AesCmd{}
				err := json.Unmarshal([]byte(pac.Json), &cmd)
				if nil != err {
					fmt.Println("Json 转 Cmd 失败", err)
					continue
				}

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

func AuthorizeConn(lsn *TcpListener, conn *net.Conn) *AesTcpClient {
	var name, password string

	ptc := NewAesTcpClientWithConn(conn)
	fmt.Println("Received client:", (*conn).RemoteAddr())
	ptc.StartWaitLoop()

	cmd := AesCmd{IsOK: true}
	cmd.Data = ptc.Ecc.EccKey.PublicKey.Hex(true)
	jdata, _ := json.Marshal(cmd)
	pkg := ptc.SendJsonAndWait(GetNexPacSN(), Cmd_GetPubKey, string(jdata), nil, 3000)
	if nil == pkg {
		fmt.Println("Failed to request public key")
		ptc.Close()
		return nil
	}

	fmt.Println("Received:", pkg.Json)
	var cmdRslt AesCmd
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

	cmd.Data = time.Now().Unix()
	jdata, _ = json.Marshal(cmd)
	pkg = ptc.SendJsonAndWait(GetNexPacSN(), Cmd_GetPrivateKey, string(jdata), nil, 3000)
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

	rslt := AesCmd{IsOK: false}
	for idx := 0; idx < 1; idx++ {
		//请求用户名密码
		cmd.Data = time.Now().Unix()
		jdata, _ = json.Marshal(cmd)
		pkg = ptc.SendJsonAndWait(GetNexPacSN(), Cmd_GetUserNamePwd, string(jdata), nil, 3000)
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
		if nil == lsn || nil == lsn.OnAuthorize || !lsn.OnAuthorize(name, password) {
			rslt.IsOK = false
			rslt.Msg = "name or password is not correct"
			break
		}

		rslt.IsOK = true
	}

	//发送认证结果
	jdata, _ = json.Marshal(rslt)
	ptc.SendJson(GetNexPacSN(), Cmd_AuthorizeResult, string(jdata), nil)

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
