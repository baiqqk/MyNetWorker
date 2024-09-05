package networker

import (
	"container/list"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type PackagedTcpClient struct {
	tcpClientBase

	curPacSN uint16
	lckSN    sync.Mutex

	recLock    sync.Mutex
	queLock    sync.Mutex
	workerLock sync.Mutex
	pacQueue   *list.List

	ansLock  sync.Mutex
	waitLock sync.Mutex
	waitChan map[uint16]*chan bool
	answer   map[uint16]*Package

	readPacChan  chan bool
	OnOnePackage func(tcp *PackagedTcpClient, pacSN uint16, cmd uint16, data []byte)
}

func (tcp *PackagedTcpClient) GetNexPacSN() uint16 {
	tcp.lckSN.Lock()
	defer tcp.lckSN.Unlock()

	tcp.curPacSN++
	if tcp.curPacSN > 32760 {
		tcp.curPacSN = 0
	}

	return tcp.curPacSN
}

func (tcp *PackagedTcpClient) GetNexPacSNJava() int {
	return int(tcp.GetNexPacSN())
}

func NewClient(conn *net.Conn) *PackagedTcpClient {
	tcp := PackagedTcpClient{}
	tcp.conn = conn
	tcp.pacQueue = list.New()
	tcp.answer = make(map[uint16]*Package)
	tcp.waitChan = make(map[uint16]*chan bool)

	// tcp.reader = bufio.NewReader(*conn)
	tcp.readPacChan = make(chan bool, 10)

	return &tcp
}

func (tcp *PackagedTcpClient) Connect(svr string, port int, msWait int) bool {
	tcp.queLock.Lock()
	if nil == tcp.pacQueue {
		tcp.pacQueue = list.New()
	}
	tcp.queLock.Unlock()

	tcp.ansLock.Lock()
	if nil == tcp.answer {
		tcp.answer = make(map[uint16]*Package)
	}
	tcp.ansLock.Unlock()

	tcp.waitLock.Lock()
	if nil == tcp.waitChan {
		tcp.waitChan = make(map[uint16]*chan bool)
		tcp.readPacChan = make(chan bool, 10)
	}
	tcp.waitLock.Unlock()

	return tcp.tcpClientBase.Connect(svr, port, msWait)
}

func (tcp *PackagedTcpClient) StartWaitLoop() {
	go tcp.waitLoop()
}

func (tcp *PackagedTcpClient) SendJava(pacSN int, cmd int, data []byte) bool {
	return tcp.Send(uint16(pacSN), uint16(cmd), data)
}

func (tcp *PackagedTcpClient) Send(pacSN uint16, cmd uint16, data []byte) bool {
	stream := PacStream(pacSN, cmd, data)

	count := tcp.Write(stream)

	return count == len(stream)
}

func (tcp *PackagedTcpClient) SendAndWaitJava(pacSN int, cmd int, data []byte, msWait int) *Package {
	return tcp.SendAndWait(uint16(pacSN), uint16(cmd), data, msWait)
}

func (tcp *PackagedTcpClient) SendAndWait(pacSN uint16, cmd uint16, data []byte, msWait int) *Package {
	has := false
	ch := make(chan bool)
	ansSN := uint16(0x8000 | pacSN)
	//清理旧的回应包
	tcp.ansLock.Lock()
	if nil == tcp.answer {
		tcp.answer = make(map[uint16]*Package)
	} else {
		_, has = tcp.answer[pacSN]
		if has {
			delete(tcp.answer, pacSN)
		}
		_, has = tcp.answer[ansSN]
		if has {
			delete(tcp.answer, ansSN)
		}
	}
	tcp.ansLock.Unlock()

	//清理旧的等待信号
	tcp.waitLock.Lock()
	if nil == tcp.waitChan {
		tcp.waitChan = map[uint16]*chan bool{}
	} else {
		_, has = tcp.waitChan[pacSN]
		if has {
			delete(tcp.waitChan, pacSN)
		}
		_, has = tcp.waitChan[ansSN]
		if has {
			delete(tcp.waitChan, ansSN)
		}
	}
	//添加新的等待信号
	tcp.waitChan[ansSN] = &ch
	tcp.waitLock.Unlock()

	//发送指令数据
	tcp.Send(pacSN, cmd, data)

	var pac *Package

	//等待结果
	select {
	case <-ch:
		pac, has = tcp.answer[ansSN]
		if !has {
			pac = nil
		} else {
			delete(tcp.answer, ansSN)
		}
	case <-time.After(time.Duration(int64(msWait) * int64(time.Millisecond))):
		pac = nil
		has = false
	}

	delete(tcp.waitChan, ansSN)

	return pac
}

func (tcp *PackagedTcpClient) waitLoop() {
	// fmt.Println("PackagedTcpClient.waitLoop Begin")
	if !tcp.recLock.TryLock() {
		fmt.Println("PackagedTcpClient.waitLoop End due to no lock")
		return
	}
	defer func() {
		tcp.recLock.Unlock()
		// fmt.Println("PackagedTcpClient.waitLoop End")
	}()

	if nil == tcp.conn /*|| nil == tcp.reader*/ {
		return
	}

	var pacSN uint16
	var cmd uint16
	var dataLen uint32
	var data []byte
	var err error
	buf := make([]byte, 8)

	for nil != tcp.conn {
		// fmt.Println("PackagedTcpClient.waitLoop 循环开始")
		//读0xAE
		for nil != tcp.conn {
			buf[0] = 0
			// fmt.Println("PackagedTcpClient.waitLoop 读0xAE Begin buf[0]=", buf[0])
			err = tcp.ReadDataWithTimeOut(1, buf, 60*60*1000) //1小时等待新数据
			// fmt.Println("PackagedTcpClient.waitLoop 读0xAE End buf[0]=", buf[0])
			if nil != err {

				if strings.Contains(err.Error(), "timeout") {
					// fmt.Println("PackagedTcpClient.waitLoop 读0xAE timeout", err)
					//如果没有接收到任何数据会产生超时错误，忽略此错误，继续等待数据
					continue
				}

				fmt.Println("PackagedTcpClient.waitLoop 读AE异常", err)

				if strings.Contains(err.Error(), "EOF") {
					tcp.Close()
					// tcp.reader = nil
					tcp.readPacChan <- true
					return
				}
			}
			if buf[0] != 0xAE {
				fmt.Println("非包头数据0xAE", buf[0])
				continue
			}
			break
		}
		// fmt.Println("PackagedTcpClient.waitLoop 收到数据，开始解包")
		//读0x86
		for {
			// fmt.Println("PackagedTcpClient.waitLoop 读0x86")
			err = tcp.ReadData(1, buf)
			if nil != err {
				fmt.Println("PackagedTcpClient.waitLoop 读86异常", err)

				if strings.Contains(err.Error(), "EOF") {
					tcp.Close()
					tcp.readPacChan <- true
					return
				}
			}
			if buf[0] == 0x86 {
				break
			} else if buf[0] == 0xAE {
				continue
			}
		}
		if buf[0] != 0x86 {
			fmt.Println("非包头数据0x86", buf[0])
			continue
		}

		//读PacSN
		err = tcp.ReadData(2, buf)
		if nil != err {
			fmt.Println("PackagedTcpClient.waitLoop 读PacSN异常", err)

			if strings.Contains(err.Error(), "EOF") {
				tcp.Close()
				tcp.readPacChan <- true
				return
			}
			continue
		}
		pacSN = uint16(buf[0]) << 8
		pacSN |= uint16(buf[1])

		//读cmd
		err = tcp.ReadData(2, buf)
		if nil != err {
			fmt.Println("PackagedTcpClient.waitLoop 读cmd异常", err)

			if strings.Contains(err.Error(), "EOF") {
				tcp.Close()
				tcp.readPacChan <- true
				return
			}
			continue
		}
		cmd = uint16(buf[0]) << 8
		cmd |= uint16(buf[1])

		//读dataLen
		err = tcp.ReadData(4, buf)
		if nil != err {
			fmt.Println("PackagedTcpClient.waitLoop 读dataLen异常", err)

			if strings.Contains(err.Error(), "EOF") {
				tcp.Close()
				tcp.readPacChan <- true
				return
			}
			continue
		}
		dataLen = uint32(buf[0]) << 24
		dataLen |= uint32(buf[1]) << 16
		dataLen |= uint32(buf[2]) << 8
		dataLen |= uint32(buf[3])

		//读data
		data = make([]byte, dataLen)
		err = tcp.ReadData(dataLen, data)
		if nil != err {
			fmt.Println("PackagedTcpClient.waitLoop 读dataLen异常", err)

			if strings.Contains(err.Error(), "EOF") {
				tcp.Close()
				tcp.readPacChan <- true
				return
			}
			continue
		}

		pac := Package{PacSN: pacSN, Data: data, Cmd: cmd}

		//回复包保存到结果字典中
		isWaitPac := false
		var ch *chan bool
		if (0x8000 & pacSN) > 0 {
			tcp.waitLock.Lock()
			ch, isWaitPac = tcp.waitChan[pacSN]
			if isWaitPac {
				delete(tcp.waitChan, pacSN)
			}
			tcp.waitLock.Unlock()

			if isWaitPac {
				// fmt.Println("收到回复包保存到结果字典 PacSN=", pacSN&0x7FFF)
				tcp.ansLock.Lock()
				tcp.answer[pacSN] = &pac
				tcp.ansLock.Unlock()

				(*ch) <- true
			}
		}

		if !isWaitPac {
			//非回复包放入队列
			pacCount := 0
			//入队列
			// fmt.Println("收到信息包保存到队列 PacSN=", pacSN&0x7FFF)
			tcp.queLock.Lock()
			if nil == tcp.pacQueue {
				tcp.pacQueue = list.New()
			}
			tcp.pacQueue.PushBack(&pac)
			pacCount = tcp.pacQueue.Len()
			tcp.queLock.Unlock()

			//有回调函数则通过回调函数通知调用方；否则通过信号通知取包线程
			if nil == tcp.OnOnePackage {
				//发送信号唤醒取包线程
				// fmt.Println("没有回调函数")
				if pacCount == 1 {
					// fmt.Println("发送信号唤醒取包线程")
					tcp.readPacChan <- true
				}
			} else {
				// fmt.Println("通过回调函数通知调用方")
				go tcp.invokePackageWorker()
			}
		}
	}
}

func (tcp *PackagedTcpClient) invokePackageWorker() {
	//单协程处理包队列
	if !tcp.workerLock.TryLock() {
		return
	}

	for {
		if tcp.pacQueue.Len() <= 0 {
			break
		}

		tcp.queLock.Lock()
		el := tcp.pacQueue.Front()
		tcp.pacQueue.Remove(el)
		tcp.queLock.Unlock()

		pac := el.Value.(*Package)

		if nil != tcp.OnOnePackage {
			tcp.OnOnePackage(tcp, pac.PacSN, pac.Cmd, pac.Data)
		}
	}

	tcp.workerLock.Unlock()

	if tcp.pacQueue.Len() > 0 {
		go tcp.invokePackageWorker()
	}
}

func (tcp *PackagedTcpClient) ReadPackage() *Package {
	return tcp.readPackage(0)
}

func (tcp *PackagedTcpClient) readPackage(msTimeOut int) *Package {
	if tcp.pacQueue.Len() <= 0 {
		if msTimeOut <= 0 {
			<-tcp.readPacChan
		} else {
			//等待结果
			select {
			case <-tcp.readPacChan:
			case <-time.After(time.Duration(int64(msTimeOut) * int64(time.Millisecond))):
				return nil
			}
		}
	}

	tcp.queLock.Lock()
	defer tcp.queLock.Unlock()

	if tcp.pacQueue.Len() > 0 {

		el := tcp.pacQueue.Front()
		tcp.pacQueue.Remove(el)
		pac := el.Value.(*Package)

		return pac
	}

	return nil
}
