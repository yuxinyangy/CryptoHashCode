package des

import (
	"CryptoHashCode/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
 *将要加密的数据使用des算法加密，并将密文返回
 */

func DesEncrypt (data,key []byte)([]byte,error){
	block,err :=des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	//填充后的数据
	originData := utils.PKCS5EndPadding(data,block.BlockSize())
	//实例化加密模式
	mode :=cipher.NewCBCEncrypter(block,key)
	//加密
	dst := make([]byte,len(originData))
	mode.CryptBlocks(dst,originData)
	return dst,nil
}

/**
 *使用des算法对密文进行解密，并将明文返回
 */

func DesDecrypt (data,key []byte) ([]byte,error)  {
	block,err := des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	blockMode := cipher.NewCBCDecrypter(block,key)
	originData := make([]byte,len(data))
	blockMode.CryptBlocks(originData,data)
	originData = utils.PKCS5UnPadding(originData,block.BlockSize())
	return originData,nil
}
