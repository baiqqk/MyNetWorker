package networker

import "net"

type UdpPackage struct {
	Data       []byte
	RemoteIP   int
	RemotePort int
}

func (pac *UdpPackage) GetIPv4Addr() *net.UDPAddr {
	return ToIPv4(pac.RemoteIP, pac.RemotePort)
}

func (pac *UdpPackage) SetIPv4Addr(addr *net.UDPAddr) {
	pac.RemotePort = addr.Port

	data := []byte(addr.IP.To4())
	pac.RemoteIP = int((int(data[0]) << 24) | (int(data[1]) << 16) | (int(data[2]) << 8) | (int(data[3])))
}
