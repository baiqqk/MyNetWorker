package networker

import (
	"fmt"
	"net"
)

func ToIPv4(ip int, port int) *net.UDPAddr {
	addr := &net.UDPAddr{
		IP:   net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)),
		Port: port,
		Zone: "",
	}

	return addr
}

func GetNetwork(ipnet *net.IPNet) int {

	data := []byte(ipnet.Mask)
	mask := int((int(data[0]) << 24) | (int(data[1]) << 16) | (int(data[2]) << 8) | (int(data[3])))

	data = []byte(ipnet.IP.To4())
	ip := int((int(data[0]) << 24) | (int(data[1]) << 16) | (int(data[2]) << 8) | (int(data[3])))
	network := mask & ip

	return network
}

func GetBroadcastIP(ipnet *net.IPNet) int {

	data := []byte(ipnet.Mask)
	mask := int((int(data[0]) << 24) | (int(data[1]) << 16) | (int(data[2]) << 8) | (int(data[3])))

	data = []byte(ipnet.IP.To4())
	ip := int((int(data[0]) << 24) | (int(data[1]) << 16) | (int(data[2]) << 8) | (int(data[3])))
	network := mask & ip

	tmp := ^mask
	baddr := network | tmp

	return baddr
}

func GetLocalIPv4() []net.IPNet {
	var err error
	var ipv4 []net.IPNet

	var (
		addrs   []net.Addr
		addr    net.Addr
		ipNet   *net.IPNet // IP地址
		isIpNet bool
	)
	// 获取所有网卡
	if addrs, err = net.InterfaceAddrs(); err != nil {
		fmt.Println("获取网卡地址失败", err)
		return nil
	}

	// fmt.Println(addrs)

	// 取第一个非lo的网卡IP
	for _, addr = range addrs {
		// 这个网络地址是IP地址: ipv4, ipv6
		ipNet, isIpNet = addr.(*net.IPNet)
		if !isIpNet {
			// fmt.Println(ipNet, "不是IP地址")
			continue
		}
		if ipNet.IP.IsLoopback() {
			// fmt.Println(ipNet, "是Loopback")
			continue
		}
		// 跳过IPV6
		if ipNet.IP.To4() == nil {
			continue
		}

		// fmt.Println(ipNet, "是IPv4地址")
		ipv4 = append(ipv4, *ipNet)
	}

	return ipv4
}
