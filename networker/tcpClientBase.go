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
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type tcpClientBase struct {
	conn *net.Conn

	ClientFlag string

	// reader *bufio.Reader
	User            *LoginUserInfo
	lastSendTime    time.Time
	lastReceiveTime time.Time

	OnClosed func()
}

func (tcp *tcpClientBase) IsConnected() bool {
	return nil != tcp.conn
}

func (tcp *tcpClientBase) GetLastReceiveTime() time.Time {
	return tcp.lastReceiveTime
}

func (tcp *tcpClientBase) onClosedHandler() {
	fmt.Println("连接关闭")
	if nil != tcp.OnClosed {
		tcp.OnClosed()
	}
}

//export Version
// func (tcp *tcpClientBase) Version() string {
// 	return "测试Version 1"
// }

func (tcp *tcpClientBase) GetConn() *net.Conn {
	return tcp.conn
}

func (tcp *tcpClientBase) Connect(svr string, port int, msWait int) bool {
	if nil != tcp.conn /*&& nil != tcp.reader*/ {
		return true
	}

	conn, err := net.DialTimeout("tcp", svr+":"+strconv.Itoa(port), time.Duration(int64(msWait)*int64(time.Millisecond)))
	if nil != err {
		fmt.Println("连接失败", svr, port, err)
		return false
	}

	tcp.conn = &conn
	// tcp.reader = bufio.NewReader(conn)
	// tcp.reader.Discard(tcp.reader.Buffered())

	tcp.lastReceiveTime = time.Now()

	return true
}

func (tcp *tcpClientBase) Close() {
	if nil == tcp.conn {
		return
	}

	(*tcp.conn).Close()
	tcp.conn = nil
	// tcp.reader = nil

	tcp.onClosedHandler()
}

func (tcp *tcpClientBase) Write(data []byte) int {
	return tcp.WriteWithTimeOut(data, 6000)
}

func (tcp *tcpClientBase) WriteWithTimeOut(data []byte, msWait int) int {
	if nil == tcp.conn || nil == data {
		return 0
	}

	conn := *tcp.conn
	if msWait > 0 {
		err := conn.SetWriteDeadline(time.Now().Add(time.Duration(int64(msWait) * int64(time.Millisecond))))
		if nil != err {
			fmt.Println("TcpClinetBase.WriteWithTimeOut 设置超时时间异常", err)
		}
	} else {
		err := conn.SetWriteDeadline(time.Now().Add(time.Duration(int64(24) * int64(time.Hour))))
		if nil != err {
			fmt.Println("TcpClinetBase.WriteWithTimeOut 设置永远不超时异常", err)
		}
	}

	totalLen := len(data)
	totalSend := 0

	// fmt.Println("TcpClinetBase.WriteWithTimeOut 发送", data)
	for totalSend < totalLen {
		count, err := conn.Write(data[totalSend:])
		if nil != err {
			if errors.Is(err, io.ErrClosedPipe) || strings.Contains(err.Error(), "broken pipe") {
				tcp.Close()
			}
			fmt.Println("TcpClinetBase.WriteWithTimeOut 异常", err)
			return -1
		}

		totalSend += count
	}

	tcp.lastSendTime = time.Now()

	return totalSend
}

func (tcp *tcpClientBase) ReadData(dataLen uint32, buf []byte) error {
	return tcp.ReadDataWithTimeOut(dataLen, buf, 1000)
}

func (tcp *tcpClientBase) ReadDataWithTimeOut(dataLen uint32, buf []byte, msWait int) error {
	if nil == tcp.conn {
		return nil
	}
	con := *tcp.conn

	var err error
	var count int
	var totalRead uint32

	count = 0
	totalRead = 0

	// fmt.Println("tcpClientBase.readDataWithTimeOut for begin dataLen=", dataLen)
	for totalRead < dataLen {
		// fmt.Println("tcpClientBase.readDataWithTimeOut SetDeadline")
		if totalRead <= 0 {
			con.SetDeadline(time.Now().Add(time.Duration(int64(msWait) * int64(time.Millisecond))))
		} else {
			con.SetDeadline(time.Now().Add(time.Duration(50 * time.Millisecond)))
		}
		// fmt.Println("tcpClientBase.readDataWithTimeOut Read totalRead=", totalRead)
		count, err = con.Read(buf[totalRead:dataLen])
		// fmt.Println("tcpClientBase.readDataWithTimeOut Read count=", count)
		if nil != err {
			// fmt.Println("tcpClientBase.readDataWithTimeOut err ", err)
			break
		}
		tcp.lastReceiveTime = time.Now()
		totalRead += uint32(count)
	}
	// fmt.Println("tcpClientBase.readDataWithTimeOut for end")

	return err
}

func (tcp *tcpClientBase) ReadLineWithTimeOut(msWait int) (string, error) {
	if nil == tcp.conn {
		return "", net.ErrClosed
	}
	con := *tcp.conn

	var err error
	var count int
	var totalRead uint32
	var buf []byte

	count = 0
	totalRead = 0
	buf = make([]byte, 1024*1024*1) //1M缓存

	// fmt.Println("tcpClientBase.readDataWithTimeOut for begin dataLen=", dataLen)
	for totalRead < uint32(len(buf)) {
		// fmt.Println("tcpClientBase.readDataWithTimeOut SetDeadline")
		if totalRead <= 0 {
			con.SetDeadline(time.Now().Add(time.Duration(int64(msWait) * int64(time.Millisecond))))
		} else {
			con.SetDeadline(time.Now().Add(time.Duration(50 * time.Millisecond)))
		}
		// fmt.Println("tcpClientBase.readDataWithTimeOut Read totalRead=", totalRead)
		count, err = con.Read(buf[totalRead : totalRead+1])
		// fmt.Println("tcpClientBase.readDataWithTimeOut Read count=", count)
		if nil != err {
			// fmt.Println("tcpClientBase.readDataWithTimeOut err ", err)
			break
		}
		tcp.lastReceiveTime = time.Now()
		totalRead += uint32(count)

		if buf[totalRead-1] == '\n' {
			break
		}
	}
	// fmt.Println("tcpClientBase.readDataWithTimeOut for end")

	if totalRead > 0 {
		return string(buf[0:totalRead]), err
	}
	return "", err
}
