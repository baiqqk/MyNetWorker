package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"main/networker"
	"net"
	"time"

	ecies "github.com/ecies/go/v2"
)

//打包aar命令: gomobile bind -target=android .

func main() {
	UdpDemo()
	TcpDemo()

	for {
		time.Sleep(time.Second * 3)
	}
}

func UdpDemo() {
	udpsvr1 := networker.UdpServer{}
	udpsvr1.OnDataReceived = func(svr *networker.UdpServer, pac *networker.UdpPackage) {
		fmt.Println("udpsvr1 Received:", string(pac.Data))
	}
	udpsvr1.Start(6789)

	udpsvr2 := networker.UdpServer{}
	udpsvr2.OnDataReceived = func(svr *networker.UdpServer, pac *networker.UdpPackage) {
		fmt.Println("udpsvr2 Received:", string(pac.Data))
		svr.Send([]byte("I got "+string(pac.Data)), networker.ToIPv4(pac.RemoteIP, pac.RemotePort))
	}
	udpsvr2.Start(7890)

	go func() {
		dst := net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 7890,
		}

		for {
			udpsvr1.Send([]byte(time.Now().Format("15:04:05")), &dst)

			time.Sleep(time.Second * 3)
		}
	}()
}

func TcpDemo() {
	lsnr := networker.TcpListener{}
	lsnr.OnClientAccepted = func(conn *net.Conn) {
		tmBegin := time.Now()
		c := AuthorizeConn(conn)

		fmt.Println(time.Now(), "Authorize cost time:", time.Since(tmBegin))

		if nil != c {
			client = c
			client.SetEccPackageHandler(clientPkgHandler)
		}
	}
	lsnr.Start(5868)

	cli := networker.EccTcpClient{}
	if !cli.Login("127.0.0.1", 5868, "admin", "admin", 3000) {
		fmt.Println("Failed to uthorize")
		return
	}

	go func() {
		cmd := networker.EccCmd{
			Cmd:  networker.Cmd_Test,
			Data: nil,
			IsOK: true,
			Msg:  "Now is " + time.Now().Format("15:04:05"),
		}

		jstr, err := json.Marshal(cmd)
		if nil != err {
			fmt.Println(err)
		}

		for {
			pac := cli.SendJsonAndWait(networker.GetNexPacSN(), string(jstr), nil, 3000)
			if nil != pac {
				fmt.Println("cli got answer: ", string(pac.Json))
			}

			time.Sleep(time.Second * 3)
		}
	}()
}

func AuthorizeConn(conn *net.Conn) *networker.EccTcpClient {
	var name, password string

	ptc := networker.NewEccTcpClientWithConn(conn)
	fmt.Println("Received client:", (*conn).RemoteAddr())
	ptc.StartWaitLoop()

	cmd := networker.EccCmd{IsOK: true}
	cmd.Cmd = 1
	cmd.Data = ptc.Ecc.EccKey.PublicKey.Hex(true)
	jdata, _ := json.Marshal(cmd)
	pkg := ptc.SendJsonAndWait(networker.GetNexPacSN(), string(jdata), nil, 3000)
	if nil == pkg {
		fmt.Println("Failed to request public key")
		ptc.Close()
		return nil
	}

	fmt.Println("Received:", pkg.Json)
	var cmdRslt networker.EccCmd
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

	cmd.Cmd = networker.Cmd_GetPrivateKey
	cmd.Data = time.Now().Unix()
	jdata, _ = json.Marshal(cmd)
	pkg = ptc.SendJsonAndWait(networker.GetNexPacSN(), string(jdata), nil, 3000)
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

	rslt := networker.EccCmd{IsOK: false}
	rslt.Cmd = networker.Cmd_AuthorizeResult
	for idx := 0; idx < 1; idx++ {
		//请求用户名密码
		cmd.Cmd = networker.Cmd_GetUserNamePwd
		cmd.Data = time.Now().Unix()
		jdata, _ = json.Marshal(cmd)
		pkg = ptc.SendJsonAndWait(networker.GetNexPacSN(), string(jdata), nil, 3000)
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
		if name != "admin" && password != "admin" {
			rslt.IsOK = false
			rslt.Msg = "name or password is not correct"
			break
		}

		rslt.IsOK = true
	}

	//发送认证结果
	jdata, _ = json.Marshal(rslt)
	ptc.SendJson(networker.GetNexPacSN(), string(jdata), nil)

	if rslt.IsOK {
		ptc.User = &networker.LoginUserInfo{ID: 0, Name: name}
		fmt.Println("Authorize OK")
		return ptc
	} else {
		fmt.Println("Failed to authorize:", rslt.Msg)
		ptc.Close()
		return nil
	}
}

var client *networker.EccTcpClient

func clientPkgHandler(tcp *networker.EccTcpClient, pkg *networker.EccPackage) {
	fmt.Println("clientPkgHandler Received: SN=", pkg.PacSN, " JSON=", pkg.Json, "len(ExtData)=", len(pkg.ExtData))

	cmd := networker.EccCmd{
		Cmd:  networker.Cmd_Test,
		Data: nil,
		IsOK: true,
		Msg:  "eccclient got " + pkg.Json,
	}

	jstr, err := json.Marshal(cmd)
	if nil != err {
		fmt.Println(err)
	}

	tcp.SendJson(0x8000|pkg.PacSN, string(jstr), nil)
}
