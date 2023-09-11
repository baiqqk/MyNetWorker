package networker

import (
	"fmt"

	ecies "github.com/ecies/go/v2"
)

type EccPackage struct {
	PacSN       uint16
	IsEncrypted bool
	Json        string
	ExtData     []byte
}

func (pkg *EccPackage) ToAesStream(aesKey []byte) []byte {
	//包格式：1字节标识位 + 2字节Json长度(小端结尾) + Json数据 + ExtData

	jsonData := []byte(pkg.Json)
	jsonLen := 0
	if nil != jsonData {
		jsonLen = len(jsonData)
	}

	flag := make([]byte, 3)
	if pkg.IsEncrypted {
		flag[0] = 1
		enData, err := RandomEncrypt(jsonData, aesKey)
		if nil != err {
			fmt.Println("FurisonPackage.ToAesStream 加密Json异常", err)
			return nil
		}

		jsonData = enData
		jsonLen = len(jsonData)
	} else {
		flag[0] = 0
	}
	flag[1] = byte(jsonLen >> 8)
	flag[2] = byte(jsonLen)

	return bytesCombine2(flag, jsonData, pkg.ExtData)
}

func (pkg *EccPackage) ToEccStream(eccKey *ecies.PublicKey) []byte {
	//包格式：1字节标识位 + 2字节Json长度(小端结尾) + Json数据 + ExtData

	jsonData := []byte(pkg.Json)
	jsonLen := 0
	if nil != jsonData {
		jsonLen = len(jsonData)
	}

	flag := make([]byte, 3)
	if pkg.IsEncrypted {
		flag[0] = 1
		enData, err := ecies.Encrypt(eccKey, jsonData)
		if nil != err {
			fmt.Println("FurisonPackage.ToEccStream 加密Json异常", err)
			return nil
		}

		jsonData = enData
		jsonLen = len(jsonData)
	} else {
		flag[0] = 0
	}
	flag[1] = byte(jsonLen >> 8)
	flag[2] = byte(jsonLen)

	return bytesCombine2(flag, jsonData, pkg.ExtData)
}

func (pac *EccPackage) SetPacSN(val int) {
	pac.PacSN = uint16(pac.PacSN)
}

func (pac *EccPackage) GetPacSN() int {
	return int(pac.PacSN)
}
