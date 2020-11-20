package aes

import (
	"CryptoHashCode/utils"
	"crypto/aes"
	"crypto/cipher"
)

/**
 *将要加密的数据使用aes算法加密，并将密文返回
 */

func AesEncrypt(data,key []byte)([]byte,error)  {
	block,err := aes.NewCipher(key)
	if err != nil {
		return nil,err
	}
	originData := utils.PKCS5EndPadding(data,block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	cipherText := make([]byte,len(originData))
	mode.CryptBlocks(cipherText,originData)
	return cipherText,nil
}

/**
 *使用aes算法对密文进行解密，并将明文返回
 */

func AesDecrypt(data, key []byte) ([]byte,error) {
	block,err := aes.NewCipher(key)
	if err != nil {
		return nil,err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	originData := make([]byte,len(data))
	blockMode.CryptBlocks(originData,data)
	originData = utils.PKCS5UnPadding(originData,block.BlockSize())
	return originData,nil
}
