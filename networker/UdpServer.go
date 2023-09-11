package networker

import (
	"container/list"
	"fmt"
	"net"
	"sync"
	"time"
)

type UdpServer struct {
	lsener         *net.UDPConn
	readLock       sync.Mutex
	OnDataReceived func(svr *UdpServer, pac *UdpPackage)

	queLock     sync.Mutex
	workerLock  sync.Mutex
	pacQueue    *list.List
	readPacChan chan bool
}

func (udp *UdpServer) IsListening() bool {
	return nil != udp.lsener
}

func (udp *UdpServer) Start(port int) bool {
	udp.Stop()

	lsener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: port,
	})
	if nil != err {
		fmt.Println("启动监听失败 port=", port, err)
		return false
	}

	udp.lsener = lsener

	udp.readPacChan = make(chan bool, 10)
	go udp.readDataLoop()

	return true
}

func (udp *UdpServer) Stop() {
	if nil == udp.lsener {
		return
	}

	err := (*udp.lsener).Close()
	if nil != err {
		fmt.Println("停止监听失败 Addr=", (*udp.lsener).LocalAddr().String(), err)
	}

	udp.lsener = nil

	udp.readPacChan <- true
}

func (udp *UdpServer) readDataLoop() {
	var buf []byte

	defer func() {
		udp.readLock.Unlock()
	}()

	if nil == udp.lsener {
		return
	}

	if !udp.readLock.TryLock() {
		return
	}

	buf = make([]byte, 1024*64) //UDP包最大64K

	for nil != udp.lsener {
		dataLen, raddr, err := (*udp.lsener).ReadFromUDP(buf)
		if nil != err {
			fmt.Println("读取数据异常", err)
			continue
		}

		if dataLen <= 0 {
			continue
		}

		pac := UdpPackage{}
		pac.Data = make([]byte, dataLen)
		copy(pac.Data, buf)
		pac.SetIPv4Addr(raddr)

		//非回复包放入队列
		pacCount := 0
		//入队列
		// fmt.Println("收到信息包保存到队列 PacSN=", pacSN&0x7FFF)
		udp.queLock.Lock()
		if nil == udp.pacQueue {
			udp.pacQueue = list.New()
		}
		udp.pacQueue.PushBack(&pac)
		pacCount = udp.pacQueue.Len()
		udp.queLock.Unlock()

		//有回调函数则通过回调函数通知调用方；否则通过信号通知取包线程
		if nil == udp.OnDataReceived {
			//发送信号唤醒取包线程
			// fmt.Println("没有回调函数")
			if pacCount == 1 {
				// fmt.Println("发送信号唤醒取包线程")
				udp.readPacChan <- true
			}
		} else {
			// fmt.Println("通过回调函数通知调用方")
			go udp.invokePackageWorker()
		}
	}
}

func (udp *UdpServer) invokePackageWorker() {
	//单协程处理包队列
	if !udp.workerLock.TryLock() {
		return
	}

	for {
		if udp.pacQueue.Len() <= 0 {
			break
		}

		udp.queLock.Lock()
		el := udp.pacQueue.Front()
		udp.pacQueue.Remove(el)
		udp.queLock.Unlock()

		pac := el.Value.(*UdpPackage)

		if nil != udp.OnDataReceived {
			udp.OnDataReceived(udp, pac)
		}
	}

	udp.workerLock.Unlock()

	if udp.pacQueue.Len() > 0 {
		go udp.invokePackageWorker()
	}
}

func (udp *UdpServer) Send(data []byte, addr *net.UDPAddr) (int, error) {
	if nil == udp.lsener {
		return 0, net.ErrClosed
	}

	return udp.lsener.WriteToUDP(data, addr)
}

func (udp *UdpServer) JavaSend(data []byte, ip int, port int) int {
	addr := ToIPv4(ip, port)

	lenSended, err := udp.lsener.WriteToUDP(data, addr)
	if nil != err {
		fmt.Println("UdpServer.JavaSend 失败", err)
		return 0
	}

	return lenSended
}

func (udp *UdpServer) JavaReadPackage() *UdpPackage {
	return udp.readPackage(0)
}

func (udp *UdpServer) readPackage(msTimeOut int) *UdpPackage {
	if nil == udp.pacQueue {
		udp.pacQueue = list.New()
	}

	if udp.pacQueue.Len() <= 0 {
		if msTimeOut <= 0 {
			<-udp.readPacChan
		} else {
			//等待结果
			select {
			case <-udp.readPacChan:
			case <-time.After(time.Duration(int64(msTimeOut) * int64(time.Millisecond))):
				return nil
			}
		}
	}

	udp.queLock.Lock()
	defer udp.queLock.Unlock()

	if udp.pacQueue.Len() > 0 {

		el := udp.pacQueue.Front()
		udp.pacQueue.Remove(el)
		pac := el.Value.(*UdpPackage)

		return pac
	}

	return nil
}

func (udp *UdpServer) Broadcast(data []byte, port int) int {

	ips := GetLocalIPv4()
	if nil == ips || len(ips) <= 0 {
		return 0
	}

	for _, ipNet := range ips {
		netaddr := GetNetwork(&ipNet)
		baddr := GetBroadcastIP(&ipNet)

		// fmt.Println("netaddr", int2ipv4String(netaddr), "baddr", int2ipv4String(baddr))

		_, err := udp.Send(data, ToIPv4(baddr, port))
		if nil != err {
			// fmt.Println(int2ipv4String(baddr), "发送失败", err)
		}

		for ip := netaddr + 1; ip < baddr; ip++ {
			go func(intIP int) {
				v4ip := ToIPv4(intIP, port)
				_, err := udp.Send(data, v4ip)
				if nil != err {
					fmt.Println(v4ip, "发送失败", err)
				} else {
					// fmt.Println(int2ipv4String(intIP), "发送成功", c)
				}
			}(ip)
		}
	}

	return 0
}
