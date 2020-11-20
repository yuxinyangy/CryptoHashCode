package ecc

import (
	"CryptoHashCode/utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

//=============椭圆曲线数字签名算法私钥生成==============//
/**
 *调用go语言的api生成一个ecdsa算法私钥
 */
func GenerateKey()(*ecdsa.PrivateKey,error) {
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve,rand.Reader)
}

//==================私钥签名，公钥验签=================//
/**
 *私钥对数据进行签名
 */
func ECDSASign(pri *ecdsa.PrivateKey,data []byte)(*big.Int,*big.Int,error)  {
	hash := utils.SHA256Hash(data)
	return ecdsa.Sign(rand.Reader,pri,hash)
}
/**
 *公钥对签名进行验签
 */
func ECDSAVerify(pub ecdsa.PublicKey,r *big.Int,s *big.Int, data []byte) bool {
	hash := utils.SHA256Hash(data)
	return ecdsa.Verify(&pub,hash,r,s)
}