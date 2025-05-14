package networker

import (
	"bytes"
)

type Package struct {
	PacSN uint16
	Data  []byte
}

//export SetPacSN
func (pac *Package) SetPacSN(val int) {
	pac.PacSN = uint16(pac.PacSN)
}

//export GetPacSN
func (pac *Package) GetPacSN() int {
	return int(pac.PacSN)
}

func (pac *Package) ToPacStream() []byte {
	return PacStream(pac.PacSN, pac.Data)
}

func PacStream(sn uint16, data []byte) []byte {
	dataLen := uint(len(data))
	head := make([]byte, 8)

	//包结构：包头2字节(0xAE86) + 序号2字节(小端结尾) + 命令2字节(小端结尾) + 数据长度4字节(小端结尾) + 数据不定长

	head[0] = 0xAE
	head[1] = 0x86
	head[2] = byte(sn >> 8)
	head[3] = byte(sn)
	head[4] = byte(dataLen >> 24)
	head[5] = byte(dataLen >> 16)
	head[6] = byte(dataLen >> 8)
	head[7] = byte(dataLen)

	return bytes.Join([][]byte{head, data}, []byte(""))
}

func PacStreamJava(sn int, data []byte) []byte {
	return PacStream(uint16(sn), data)
}
