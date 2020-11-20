package rsa

import (
	"CryptoHashCode/utils"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
)

const RSA_PRIVATE_KEY  = "RSA PRIVATE KEY"
const RSA_PUBLIC_KEY  = "RSA PUBLIC KEY"
/**
 *该函数用于生成一对RSA密钥对，并返回密钥数据
 */
func CreateRSAKey()(*rsa.PrivateKey,error)  {
	//bit:位，二进制位，比特
	//byte:字节
	var bits int
	flag.IntVar(&bits,"b",2048,"rsa密钥的长度")
	//1、私钥
	privateKey,err :=rsa.GenerateKey(rand.Reader,bits)
	if err != nil {
		return nil,err
	}
	//2、公钥
	//privateKey.PublicKey
	//3、将私钥和公钥进行返回
	return privateKey,nil
}

func GenerateKeyPem(file_name string)error  {
	//1、先生成私钥
	pri, err := CreateRSAKey()
	if err != nil {
		return err
	}
	//2、生成私钥证书
	err = generatePriPem(pri, file_name)
	if err != nil {
		return err
	}
	//3、生成公钥证书
	err = generatePubPem(pri.PublicKey, file_name)
	if err != nil {
		return err
	}
	return nil
}
/**
 *生成一个私钥证书文件
 */

func generatePriPem(pri *rsa.PrivateKey,file_name string) error {
	priBytes := x509.MarshalPKCS1PrivateKey(pri)
	block := &pem.Block{
		Type:    RSA_PRIVATE_KEY,
		Bytes:   priBytes,
	}
	file,err := os.Create("private_"+file_name+".pem")
	if err != nil {
		return err
	}
	return pem.Encode(file,block)
}

func generatePubPem(pub rsa.PublicKey,file_name string)error {
	pubBytes := x509.MarshalPKCS1PublicKey(&pub)
	block := &pem.Block{
		Type:    RSA_PUBLIC_KEY,
		Bytes:   pubBytes,
	}
	file,err := os.Create("public_"+file_name+".pem")
	if err != nil {
		return err
	}
	return pem.Encode(file,block)
}

//==================第一种组合：公钥加密，私钥解密===================//

/**
 *使用RSA算法对数据data进行加密，并返回加密后的密文
 */
func RSAEncrypt(pri *rsa.PrivateKey,data []byte)([]byte,error)  {
	return rsa.EncryptPKCS1v15(rand.Reader,&pri.PublicKey,data)
}

/**
 *使用RSA算法对密文数据进行解密，返回解密后的明文
 */
func RSADecrypt(pri *rsa.PrivateKey,cipher []byte)([]byte,error)  {
	return  rsa.DecryptPKCS1v15(rand.Reader,pri,cipher)
}

//==================第一种组合：私钥签名，公钥验签===================//
//signature:签名 n
//sign:签名 v
/**
 *使用rsa算法对数据进行签名
 */
func RSASign(pri *rsa.PrivateKey,data []byte)([]byte,error){
	hashed :=utils.MD5Hash(data)
	return rsa.SignPKCS1v15(rand.Reader,pri,crypto.MD5,hashed)
}
/**
 *使用rsa算法进行签名验证
 */
//verify:验证
func RSAVerify(pub rsa.PublicKey,data []byte,sign []byte)(bool, error)  {
	hashed :=utils.MD5Hash(data)
	verifyResult :=rsa.VerifyPKCS1v15(&pub,crypto.MD5,hashed,sign)
	return verifyResult == nil,verifyResult
}