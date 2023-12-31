package main

import (
	"encoding/json"
	"fmt"
	"main/networker"
	"net"
	"time"
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
	//username and password is admin for this demo

	lsnr := networker.TcpListener{}
	lsnr.OnAuthorize = func(name, pwd string) bool {
		return name == "admin" && pwd == "admin"
	}
	lsnr.OnClientAccepted = func(conn *net.Conn) {
		tmBegin := time.Now()
		c := networker.AuthorizeConn(&lsnr, conn)

		fmt.Println(time.Now(), "Authorize cost time:", time.Since(tmBegin))

		if nil != c {
			client = c
			client.SetAesPackageHandler(clientPkgHandler)
		}
	}
	lsnr.Start(5868)

	cli := networker.AesTcpClient{}
	if !cli.Login("127.0.0.1", 5868, "admin", "admin", 3000) {
		fmt.Println("Failed to authorize")
		return
	}

	go func() {
		cmd := networker.AesCmd{
			Data: nil,
			IsOK: true,
			Msg:  "Now is " + time.Now().Format("15:04:05"),
		}

		for {
			cmd.Msg = "Now is " + time.Now().Format("15:04:05")
			jstr, err := json.Marshal(cmd)
			if nil != err {
				fmt.Println(err)
			}

			pac := cli.SendJsonAndWait(networker.GetNexPacSN(), networker.Cmd_Test, string(jstr), nil, 3000)
			if nil != pac {
				fmt.Println("cli got answer: ", string(pac.Json))
			}

			time.Sleep(time.Second * 3)
		}
	}()
}

var client *networker.AesTcpClient

func clientPkgHandler(tcp *networker.AesTcpClient, pkg *networker.AesPackage) {
	fmt.Println("clientPkgHandler Received: SN=", pkg.PacSN, " JSON=", pkg.Json, " Cmd=", pkg.Cmd, "len(ExtData)=", len(pkg.ExtData))

	cmd := networker.AesCmd{
		Data: nil,
		IsOK: true,
		Msg:  "eccclient got " + pkg.Json,
	}

	jstr, err := json.Marshal(cmd)
	if nil != err {
		fmt.Println(err)
	}

	tcp.SendJson(0x8000|pkg.PacSN, networker.Cmd_Test, string(jstr), nil)
}
