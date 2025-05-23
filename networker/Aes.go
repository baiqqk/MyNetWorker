package networker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
)

//加密过程：
//  1、处理数据，对数据进行填充，采用PKCS7（当密钥长度不够时，缺几位补几个几）的方式。
//  2、对数据进行加密，采用AES加密方法中CBC加密模式
//  3、对得到的加密数据，进行base64加密，得到字符串
// 解密过程相反

// 16,24,32位字符串的话，分别对应AES-128，AES-192，AES-256 加密方法
// key不能泄露
// var pwdKey = []byte("ABCDABCDABCDABCD")

// pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

// AesEncrypt 加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AesDecrypt 解密
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// 随机加密
func RandomEncrypt(data []byte, key []byte) ([]byte, error) {

	pre_Data := make([]byte, 4)
	end_Data := make([]byte, 4)

	rand.Read(pre_Data)
	rand.Read(end_Data)

	pre_Data = append(pre_Data, data...)
	pre_Data = append(pre_Data, end_Data...)

	return AesEncrypt(pre_Data, key)
}

// 随机解密
func RandomDecrypt(data []byte, key []byte) ([]byte, error) {
	allData, error := AesDecrypt(data, key)

	if nil != error {
		return nil, error
	}

	return allData[4 : len(allData)-4], error
}

// 生成一个随机密钥
func newAesKey() []byte {
	data := make([]byte, 16)
	rand.Read(data)

	return data
}

// // encryptByAes Aes加密 后 base64 再加
// func encryptByAes(data []byte) (string, error) {
// 	res, err := aesEncrypt(data, pwdKey)
// 	if err != nil {
// 		return "", err
// 	}
// 	return base64.StdEncoding.EncodeToString(res), nil
// }

// // decryptByAes Aes 解密
// func decryptByAes(data string) ([]byte, error) {
// 	dataByte, err := base64.StdEncoding.DecodeString(data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return aesDecrypt(dataByte, pwdKey)
// }

func GetMD5(data []byte, repeats int) []byte {
	var arr [md5.Size]byte

	key := data[:]

	for repeats > 0 {
		repeats--

		arr = md5.Sum(data)
		key = arr[:]
	}

	return key
}
