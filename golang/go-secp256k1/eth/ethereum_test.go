package eth

import (
	"encoding/hex"
	"fmt"
	"github.com/issue9/assert"
	"math/big"
	"reflect"
	"testing"
)

func GetTestTransaction001() *Transaction {
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	return transaction
}

func TestNewPrivateKey001(t *testing.T) {

	privKey, err := NewPrivateKey()
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	pubKey := privKey.PubKey()
	privKeyBytes := privKey.D.Bytes()
	privKeyHex := GetPrivKeyHex(privKey)

	fmt.Println("PrivKey type:", reflect.TypeOf(privKey))
	fmt.Println("PubKey type:", reflect.TypeOf(pubKey))
	fmt.Println("PrivateKey is :", privKeyHex)

	assert.Equal(t, len(privKeyBytes), 32)
	assert.Equal(t, len(privKeyHex), 64)
}

func TestPrivKeyFromBytes001(t *testing.T) {
	privKeyHex := "0a5e1538365dadfcceee00c56adc204123826b49e330ed7094f93e981aa33873"
	d := big.NewInt(0)
	d.SetString("4689358562077529291234437905516790529628307520206566088593526793029726451827", 10)

	privKeyHexStr, err := hex.DecodeString(privKeyHex)
	assert.Nil(t, err)

	privKey, pubKey := PrivKeyFromBytes([]byte(privKeyHexStr))
	assert.NotNil(t, privKey)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.D, d)
	fmt.Println("输出私钥（未补零）：", privKey.D.Text(16))
	fmt.Println("输出私钥（补零）   ：", GetPrivKeyHex(privKey))

	// 地址，不带0x开头
	addr := GetEthAddress(pubKey)
	assert.Equal(t, addr, "de61196c288f5d494e31dd2cbae1b16769c43d86")

	// 非压缩公钥
	uncompressPubKey := GetPubKeyHex(pubKey, false)
	assert.Equal(t, uncompressPubKey, "0420be2e521e3377e4a5ed72d926586b433e9d693ea3c5baff800c876a64857aed2e94d6c5cd5d66969b0c287bde06852e598fe9c77263b78777072ed5e73cb255")

	// 压缩公钥
	compressPubKey := GetPubKeyHex(pubKey, true)
	assert.Equal(t, compressPubKey, "0320be2e521e3377e4a5ed72d926586b433e9d693ea3c5baff800c876a64857aed")
}

func TestPrivKeyFromBytes002(t *testing.T) {
	privKeyHex := "4b79fcfc4487c4fff76bed197375d29c92016968901225d932a1f2809dfd36c4"
	d := big.NewInt(0)
	d.SetString("34138998179786203154770409162353357425239089831840009188934414090616421824196", 10)

	privKeyHexStr, err := hex.DecodeString(privKeyHex)
	assert.Nil(t, err)

	privKey, pubKey := PrivKeyFromBytes([]byte(privKeyHexStr))
	assert.NotNil(t, privKey)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.D, d)
	fmt.Println("输出私钥（未补零）：", privKey.D.Text(16))
	fmt.Println("输出私钥（补零）   ：", GetPrivKeyHex(privKey))

	// 地址，不带0x开头
	addr := GetEthAddress(pubKey)
	assert.Equal(t, addr, "23998cf0d73142d764f0acff035aa85c0b9d159a")

	// 非压缩公钥
	uncompressPubKey := GetPubKeyHex(pubKey, false)
	assert.Equal(t, uncompressPubKey, "040a38cfe8f6fae592051dfd18ad2cd9bf2a0ba0c04a3126480a9c3a4db38705f2afcd9e18833eebaf3de15a15a3c36a2216c2bec2c810bd7500c8f5132fb6ddc2")

	// 压缩公钥
	compressPubKey := GetPubKeyHex(pubKey, true)
	assert.Equal(t, compressPubKey, "020a38cfe8f6fae592051dfd18ad2cd9bf2a0ba0c04a3126480a9c3a4db38705f2")
}

// 测试签名：
// v=0
func TestSign001(t *testing.T) {
	privKeyHex := "b5b3c87ad3ec91998142d32206094a4998e7d401affad5888888979b5112e05d"

	privKey, pubKey, err := PrivKeyFromHex(privKeyHex)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.NotNil(t, pubKey)
	fmt.Println("输出私钥（未补零）：", privKey.D.Text(16))
	fmt.Println("输出私钥（补零）   ：", GetPrivKeyHex(privKey))

	// 地址，不带0x开头
	addr := GetEthAddress(pubKey)
	assert.Equal(t, addr, "cc27ae1e9863ed692e0fb48845fb9d3134d8b115")

	// 非压缩公钥
	uncompressPubKey := GetPubKeyHex(pubKey, false)
	assert.Equal(t, uncompressPubKey, "04344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe972b22a005c3f0c32e8c16f7b3c6e649600554bf0847633458d33e280a7f90b0a")

	// 压缩公钥
	compressPubKey := GetPubKeyHex(pubKey, true)
	assert.Equal(t, compressPubKey, "02344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe9")

	// 执行签名
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	sigature, err := Sign(privKey, message)
	assert.Nil(t, err)

	fmt.Println("签名为：", hex.EncodeToString(sigature))
	assert.Equal(t, len(sigature), 65)
	assert.Equal(t, hex.EncodeToString(sigature), "9bb49679d6ea53f490685a0fe35140f5c412d2a1f371adc07512022557997456592a3dd156eaf7f317afdcfafa68a1b3713fe96aa860fa32cfa290e1b1da212a00")
}

// 测试签名：
// v=1
func TestSign002(t *testing.T) {
	privKeyHex := "fab8850d6b4395a7cdfb98bb1b98738128bf32b43f5b005a0a312db3983550f2"

	privKey, pubKey, err := PrivKeyFromHex(privKeyHex)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.NotNil(t, pubKey)
	fmt.Println("输出私钥（未补零）：", privKey.D.Text(16))
	fmt.Println("输出私钥（补零）   ：", GetPrivKeyHex(privKey))

	// 地址，不带0x开头
	addr := GetEthAddress(pubKey)
	assert.Equal(t, addr, "64e26a1d894d0f70a14283844e14ead4f8ca70fd")

	// 非压缩公钥
	uncompressPubKey := GetPubKeyHex(pubKey, false)
	assert.Equal(t, uncompressPubKey, "0463db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0faab833330f27144cfd0eaecc8a0e56d5d0250519946b4bc9ed8d0349a6ff47807")

	// 压缩公钥
	compressPubKey := GetPubKeyHex(pubKey, true)
	assert.Equal(t, compressPubKey, "0363db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0fa")

	// 执行签名
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	sigature, err := Sign(privKey, message)
	assert.Nil(t, err)

	fmt.Println("签名为：", hex.EncodeToString(sigature))
	assert.Equal(t, len(sigature), 65)
	assert.Equal(t, hex.EncodeToString(sigature), "ddf16a6aaa261893ba4de8ea6d46053d7b0bd294b857ddcb6fe715b50de942172d650eb24f44f78a4ea29d34d58f9b6bfce275f71369661cc3c8742ab8659c9801")
}

// 测试验签：
// v=0
func TestVerify001(t *testing.T) {
	//privKeyHex := "b5b3c87ad3ec91998142d32206094a4998e7d401affad5888888979b5112e05d"

	pubKey, err := PubKeyFromHex("04344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe972b22a005c3f0c32e8c16f7b3c6e649600554bf0847633458d33e280a7f90b0a")
	assert.Nil(t, err)
	fmt.Println("PubKey compressed=", GetPubKeyHex(pubKey, true))

	// 执行签名
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	// 签名
	signatureStr := "9bb49679d6ea53f490685a0fe35140f5c412d2a1f371adc07512022557997456592a3dd156eaf7f317afdcfafa68a1b3713fe96aa860fa32cfa290e1b1da212a00"

	signature,err := hex.DecodeString(signatureStr)
	verify, err := Verify(pubKey, message, signature)
	assert.Nil(t, err)

	fmt.Println("验证签名结果为：", verify)
}

// 测试验签：
// v=1
func TestVerify002(t *testing.T) {
	//privKeyHex := "fab8850d6b4395a7cdfb98bb1b98738128bf32b43f5b005a0a312db3983550f2"

	pubKey, err := PubKeyFromHex("0463db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0faab833330f27144cfd0eaecc8a0e56d5d0250519946b4bc9ed8d0349a6ff47807")
	assert.Nil(t, err)
	fmt.Println("PubKey compressed=", GetPubKeyHex(pubKey, true))

	// 执行签名
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	// 签名
	signatureStr := "ddf16a6aaa261893ba4de8ea6d46053d7b0bd294b857ddcb6fe715b50de942172d650eb24f44f78a4ea29d34d58f9b6bfce275f71369661cc3c8742ab8659c9801"

	signature,err := hex.DecodeString(signatureStr)
	verify, err := Verify(pubKey, message, signature)
	assert.Nil(t, err)

	fmt.Println("验证签名结果为：", verify)
}

// 恢复公钥：
// v=0
func TestERecovery001(t *testing.T) {
	//privKeyHex := "b5b3c87ad3ec91998142d32206094a4998e7d401affad5888888979b5112e05d"
    // 非压缩公钥：04344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe972b22a005c3f0c32e8c16f7b3c6e649600554bf0847633458d33e280a7f90b0a
    // 压缩公钥：   02344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe9
	// 获取测试交易数据
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	// 签名
	signatureStr := "9bb49679d6ea53f490685a0fe35140f5c412d2a1f371adc07512022557997456592a3dd156eaf7f317afdcfafa68a1b3713fe96aa860fa32cfa290e1b1da212a00"

	signature,err := hex.DecodeString(signatureStr)
	pubKey, compress, err := ERecovery(message, signature)
	assert.Nil(t, err)

	fmt.Println("是否为压缩公钥：", compress)
	fmt.Println("公钥      非压缩：", GetPubKeyHex(pubKey, false))
	fmt.Println("公钥         压缩：", GetPubKeyHex(pubKey, true))

	assert.Equal(t, GetPubKeyHex(pubKey, false), "04344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe972b22a005c3f0c32e8c16f7b3c6e649600554bf0847633458d33e280a7f90b0a")
	assert.Equal(t, GetPubKeyHex(pubKey, true), "02344885fbdd9639783787eb9a58bbe877dac02e21f67ecf720f9b621fadc0fbe9")
}

// 恢复公钥：
// v=1
func TestERecovery002(t *testing.T) {
	//privKeyHex := "fab8850d6b4395a7cdfb98bb1b98738128bf32b43f5b005a0a312db3983550f2"
	// 非压缩公钥：0463db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0faab833330f27144cfd0eaecc8a0e56d5d0250519946b4bc9ed8d0349a6ff47807
	// 压缩公钥：   0363db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0fa
	// 获取测试交易数据
	transaction := GetTestTransaction001()
	message, err := transaction.ToJSON()
	assert.Nil(t, err)

	// 签名
	signatureStr := "ddf16a6aaa261893ba4de8ea6d46053d7b0bd294b857ddcb6fe715b50de942172d650eb24f44f78a4ea29d34d58f9b6bfce275f71369661cc3c8742ab8659c9801"

	signature,err := hex.DecodeString(signatureStr)
	pubKey, compress, err := ERecovery(message, signature)
	assert.Nil(t, err)

	fmt.Println("是否为压缩公钥：", compress)
	fmt.Println("公钥      非压缩：", GetPubKeyHex(pubKey, false))
	fmt.Println("公钥         压缩：", GetPubKeyHex(pubKey, true))

	assert.Equal(t, GetPubKeyHex(pubKey, false), "0463db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0faab833330f27144cfd0eaecc8a0e56d5d0250519946b4bc9ed8d0349a6ff47807")
	assert.Equal(t, GetPubKeyHex(pubKey, true), "0363db037c7b289c9bc0764e850e2b081733d056d404cc22f2196cc3e52c98f0fa")
}