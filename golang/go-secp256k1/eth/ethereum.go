/*
利用btcec的secp256k1的纯golang实现，进行以太坊签名，验签，及恢复公钥
以太坊签名和比特币签名均是在secp256k1曲线上，但是形式不同，需要转换
 */
package eth

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/smartheye/cryptography/go-secp256k1/crypto"
	"math/big"
)

type PrivateKey = btcec.PrivateKey
type PublicKey = btcec.PublicKey

// 生成一个256位的私钥
func NewPrivateKey() (*PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(privKey), nil
}

// 将一个长度为32的数组转换为私钥
func PrivKeyFromBytes(pk []byte) (*PrivateKey,
	*PublicKey) {
	return btcec.PrivKeyFromBytes(btcec.S256(), pk)
}

// 将一个16进制的64位字符串转换为私钥
// 例如：c00f14d293ff02ebc08a91a47b8f834e185b74638b1731420f7d121d3027e245
func PrivKeyFromHex(hexstr string) (*PrivateKey,
	*PublicKey, error) {
	pk, err := hex.DecodeString(hexstr)
	if err != nil {
		return nil, nil, err
	}
	privkey, pubkey := PrivKeyFromBytes(pk)
	return privkey, pubkey, nil
}

// 通过字节转换为公钥
func PubKeyFromBytes(pk []byte) (*PublicKey, error) {
	return btcec.ParsePubKey(pk, btcec.S256())
}

// 将16进制字符串转换为公钥
func PubKeyFromHex(hexstr string) (*PublicKey, error) {
	pk, err := hex.DecodeString(hexstr)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(pk, btcec.S256())
}

// 通过公钥获取地址
// 地址是长度为40的16进制字符串，且不带0x开头
func GetEthAddress(pubKey *PublicKey) (string){
	uncompressedPubKey := pubKey.SerializeUncompressed()
	// 将非压缩公钥舍去第一位标志位（04）执行Keccak256哈希
	pubkeyHash := crypto.Keccak256(uncompressedPubKey[1:])
	// 地址为哈希后的值得后20位
	address := hex.EncodeToString(pubkeyHash[12:])
	return address
}

// 获取字符串形式的16进制私钥
// 形如：0a5e1538365dadfcceee00c56adc204123826b49e330ed7094f93e981aa33873
func GetPrivKeyHex(privKey *PrivateKey) (string){
	return  fmt.Sprintf("%064x", privKey.D)
}

// 获取字符串形式的16进制公钥
// compress : 指定是否要压缩公钥
func GetPubKeyHex(pubKey *PublicKey, compress bool) (string){
	var pubKeyBytes []byte
	if compress {
		pubKeyBytes = pubKey.SerializeCompressed()
	}else{
		pubKeyBytes = pubKey.SerializeUncompressed()
	}
	return hex.EncodeToString(pubKeyBytes)
}

// 返回以太坊签名格式的签名，签名格式和ethereumj兼容
// 参数：
// privKey：私钥
// message：签名对象字符
// 返回值：
// []byte : 签名字节数组。长度固定为65。和以太坊签名格式兼容。格式为r s v。其中r 为32字节数组，s为32字节数组，v为1个字节
// error : 异常
func Sign(privKey *PrivateKey, message []byte) ([]byte, error){
	messageHash := crypto.Keccak256(message)
	// 签名长度为65个字符。且格式为v r s
	signature, err := btcec.SignCompact(btcec.S256(), privKey, messageHash, false)
	if err!=nil{
		return nil, err
	}
	// TODO 这里没有检查s是否比N/2小
	// 在非压缩公钥签名格式下，v的值为27,28,29,30。 减去27后对应ethereumj的签名格式
	// (压缩公钥下，v的值为31,32,33,34)
	v := signature[0] - 27
	ethereumSignature := append(signature[1:], v)
	return ethereumSignature, nil
}

// 验证以太坊格式的签名，签名格式和ethereumj兼容
// 参数：
// pubKey : 公钥
// message : 签名对象字符
// signature : 签名字节数组。长度固定为65。和以太坊签名格式兼容。格式为r s v。其中r 为32字节数组，s为32字节数组，v为1个字节
// 返回值：
// bool : 是否验证正确
// error : 异常
func Verify(pubKey *PublicKey, message []byte, signature []byte) (bool, error){
	//fmt.Println(len(signature))
	messageHash := crypto.Keccak256(message)
	// 解析签名
	Rbytes := signature[0:32]
	Sbytes := signature[32:64]
	R := big.NewInt(0)
	S := big.NewInt(0)
	R.SetBytes(Rbytes)
	S.SetBytes(Sbytes)
	//fmt.Printf("r=%064x, s=%064x\n", R, S)
	sig := &btcec.Signature{R, S}
	// 验证
	result := sig.Verify(messageHash, pubKey)
	return result, nil
}

// 恢复公钥
// 参数：
// message : 签名对象字符
// signature : 签名字节数组。长度固定为65。和以太坊签名格式兼容。格式为r s v。其中r 为32字节数组，s为32字节数组，v为1个字节
// 返回值：
// PubicKey : 公钥
// bool : 是否是压缩公钥
// error : 异常
func ERecovery(message []byte, signature []byte)  (*PublicKey, bool, error) {
	messageHash := crypto.Keccak256(message)
	bitcoinSignature := make([]byte, 65, 65)
	bitcoinSignature[0] = signature[64] + 27

	for i:=0; i < 64; i++{
		bitcoinSignature[i+1] = signature[i]
	}

	return btcec.RecoverCompact(btcec.S256(), bitcoinSignature, messageHash)
}