package main

import (
	"fmt"
	"main/networker"
	"net"
	"sync"
	"time"
)

//打包aar命令: gomobile bind -target=android .

func main() {
	// UdpDemo()
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

	tcpSvr()
	tcpCli()

	for {
		time.Sleep(time.Second)
	}

}

var clients []*networker.AesTcpClient

var cntLck sync.Mutex
var totalPacTransted uint64 = 0
var PacPerSec int = 0
var secCount uint64 = 0

func tcpSvr() {
	lsnr := networker.TcpListener{}
	lsnr.OnAuthorize = func(name, pwd string) bool {
		return name == "admin" && pwd == "admin" //username and password is admin for this demo
	}
	lsnr.OnClientAccepted = func(conn *net.Conn) {
		tmBegin := time.Now()
		c := networker.AuthorizeConn(&lsnr, conn)

		fmt.Println(time.Now(), "Authorize cost time:", time.Since(tmBegin))

		if nil != c {
			clients = append(clients, c)
			c.SetAesPackageHandler(func(tcp *networker.AesTcpClient, pkg *networker.AesPackage) {
				cntLck.Lock()
				totalPacTransted++
				PacPerSec++
				cntLck.Unlock()

				tcp.SendJson(0x8000|pkg.PacSN, networker.Cmd_Test, pkg.Json, nil)
			})

			c.OnClosed = func() {
				for i := len(clients) - 1; i >= 0; i-- {
					if !clients[i].IsConnected() {
						arr := clients[:i]
						if i != len(clients)-1 {
							arr = append(arr, clients[i+1:]...)
						}
						clients = arr[:]
					}
				}
			}
		}
	}
	lsnr.Start(5868)

	go func() {
		for {
			time.Sleep(time.Second)
			secCount++

			fmt.Printf("ClientCount: %d RT-Rate: %d Avg-Rate: %d\n", len(clients), PacPerSec, totalPacTransted/secCount)
			PacPerSec = 0
		}
	}()

}

func tcpCli() {

	cli := networker.AesTcpClient{}
	if !cli.Login("127.0.0.1", 5868, "admin", "admin", 3000) {
		fmt.Println("Failed to authorize")
		return
	}

	jstr := "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" +
		"012345678901234567890123"

	// cmd := networker.AesCmd{
	// 	Data: nil,
	// 	IsOK: true,
	// 	Msg:  jstr,
	// }

	// jdata, err := json.Marshal(cmd)
	// if nil != err {
	// 	fmt.Println(err)
	// }

	// jstr = string(jdata)

	cli.SetAesPackageHandler(func(tcp *networker.AesTcpClient, pkg *networker.AesPackage) {
		// fmt.Println(pkg.Json)
	})

	go func() {
		for {
			cli.SendJson(cli.GetNexPacSN(), networker.Cmd_Test, jstr, nil)
		}
	}()
}
