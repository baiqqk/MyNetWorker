package networker

import (
	"fmt"
	"net"
	"strconv"
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
