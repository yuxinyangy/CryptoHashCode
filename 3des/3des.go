package _des

import (
	"CryptoHashCode/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
 *将要加密的数据使用3des算法加密，并将密文返回
 */

func TripleDesEncrypt(data,key []byte)([]byte,error)  {
	block,err :=des.NewTripleDESCipher(key)
	if err != nil {
		return nil,err
	}
	originData := utils.PKCS5EndPadding(data,block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	dst := make([]byte,len(originData))
	mode.CryptBlocks(dst,originData)
	return dst,nil
}

/**
 *使用3des算法对密文进行解密，并将明文返回
 */

func TripleDesDecrypt(data,key []byte)([]byte,error)  {
	block,err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil,err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	originData := make([]byte,len(data))
	blockMode.CryptBlocks(originData,data)
	originData = utils.PKCS5UnPadding(originData,block.BlockSize())
	return originData,nil
}