package networker

import (
	"fmt"

	ecies "github.com/ecies/go/v2"
)

type ECC struct {
	EccKey *ecies.PrivateKey
}

func (ecc *ECC) initKey() {
	if nil == ecc.EccKey {
		key, err := ecies.GenerateKey()
		if nil != err {
			fmt.Println("ECC.init 创建ECC私钥异常", err)
			return
		}

		ecc.EccKey = key
	}
}

func (ecc *ECC) GetPubKey() *ecies.PublicKey {
	ecc.initKey()

	return ecc.EccKey.PublicKey
}

func (ecc *ECC) Encrypt(data []byte, pubKey *ecies.PublicKey) []byte {
	code, err := ecies.Encrypt(pubKey, data)
	if nil != err {
		fmt.Println("ECC.Encrypt 加密异常", err)
		return nil
	}

	return code
}

func (ecc *ECC) Decrypt(data []byte) []byte {
	ecc.initKey()

	code, err := ecies.Decrypt(ecc.EccKey, data)
	if nil != err {
		fmt.Println("ECC.Decrypt 解密异常", err)
		return nil
	}

	return code
}
