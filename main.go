package main

import (
	"CryptoHashCode/ecc"
	"CryptoHashCode/rsa"
	"fmt"
)

func main() {
	//key := []byte("20010728")
	//arr := "余鑫洋"
	//fmt.Println("加密前",arr)
	//resultArr,_ :=des.DesEncrypt([]byte(arr),key)
	//fmt.Println("加密后:",string(resultArr))
	//resultArr,_ = des.DesDecrypt(resultArr,key)
	//fmt.Println("解密后:",string(resultArr))

	//4、RSA算法
	//fmt.Println("RSA算法:")
	//data4 := "在天愿作比翼鸟,在地愿为连理枝"
	//4.1 生成一对秘钥
	//pri,err := rsa.CreateRSAKey()
	//if err != nil {
	//	fmt.Println("rsa算法秘钥生成失败:",err.Error())
	//	return
	//}
	//4.1.5将私钥保存到文件中
	err := rsa.GenerateKeyPem("y")
	if err != nil {
		fmt.Println("生成失败")
		return
	}
	//4.2使用生成的秘钥对数据进行加密
	//cipherText4,err :=rsa.RSAEncrypt(pri,[]byte(data4))
	//if err != nil {
	//	fmt.Println("rsa算法加密失败",err.Error())
	//	return
	//}
	////4.3使用私钥进行解密
	//originalText4,err :=rsa.RSADecrypt(pri,cipherText4)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//fmt.Println("rsa算法解密成功",string(originalText4))
	//
	////4.4 使用rsa算法对数据进行签名
	//signText4, err := rsa.RSASign(pri, []byte(data4))
	//if err != nil {
	//	fmt.Println("rsa算法签名失败：", err.Error())
	//	return
	//}
	//
	////4.5 使用rsa公钥对签名进行验证
	//verifyResult, err := rsa.RSAVerify(pri.PublicKey, []byte(data4), signText4)
	//if err != nil {
	//	fmt.Println("rsa签名验证失败:", err.Error())
	//}
	//if verifyResult {
	//	fmt.Println("恭喜，rsa签名验证成功!")
	//} else {
	//	fmt.Println("抱歉，rsa签名验证失败!")
	//}

	//5、ecc算法中ecdsa数据签名算法
	priKey,err :=ecc.GenerateKey()
	if err != nil {
		fmt.Println("ecdsa生成密钥错误:",err.Error())
		return
	}
	data5 := "咿咿呀呀"
	r,s,err := ecc.ECDSASign(priKey,[]byte(data5))
	if err != nil {
		fmt.Println("签名错误",err.Error())
		return
	}
	verifyResult := ecc.ECDSAVerify(priKey.PublicKey,r,s,[]byte(data5))
	if verifyResult {
		fmt.Println("签名验证成功")
	}else{
		fmt.Println("签名验证失败")
	}
}