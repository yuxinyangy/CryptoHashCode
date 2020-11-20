package utils

import "bytes"

/**
 *为加密明文进行PCKS5尾部填充
 */

func PKCS5EndPadding(data []byte, blockSize int) []byte {
	//1、计算要填充多少个
	size := blockSize - len(data)%blockSize
	//2、准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(size)},size)
	//3、填充
	return append(data,paddingText...)
}

/**
 *为加密明文进行Zero尾部填充
 */

func ZerosEndPadding(data []byte,blockSize int) []byte  {
	//1、计算填充多少个
	size := blockSize - len(data)%blockSize
	//2、准备要填充的内容
	paddingText := bytes.Repeat([]byte{byte(0)},size)
	//3、填充
	return append(data,paddingText...)
}
/**
 *将PKCS5尾部填充的数据去除
 */

func PKCS5UnPadding(data []byte , blockSize int)[]byte  {
	clearSize := int(data[len(data)-1])
	return data[:len(data)-clearSize]
}
/**
 *将Zeros尾部填充的数据去除
 */
func ZerosUnPadding(data []byte,blockSize int)[]byte  {
	length :=blockSize - len(data)%blockSize
	return data[:(len(data)-length)]
}