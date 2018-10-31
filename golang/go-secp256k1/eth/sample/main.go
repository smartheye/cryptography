package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/smartheye/cryptography/go-secp256k1/eth"
)

func main() {
	// 例子
	/*
	输入
	   发送人Nonce
	   收款人地址
	   金额（10^18为1个单位）
	   附加信息
	   发送人签名
	（由于JSON的精度问题，这里使用字符串来存储数字）
	 */
	 var accountNonce = "1"
	 var receipt = "e2f688722675dbdf3a9094927cf0e38d5e714f02"
	 var amount = "101230000000000000000"
	 var signatureStr = "e915038870a7abeeb5578344f7031071998412131594b8122f6ee9bff1bd91865a897449b8816be1a23c4241ffc551d25436f01c248456b265f6ddcc7e14dff501"

	 // 1. 构造交易对象
	 var transaction = eth.NewTransaction(accountNonce, receipt, amount)

	 // 2. 执行序列号。这里我们使用的是JSON编码格式，不采用以太坊的RLP编码格式。
	 // 编码格式不同导致和以太坊不兼容
	 message, err := transaction.ToJSON()

	 if err!= nil {
	 	// 注意：错误处理需要通过接口定义另行处理
	 	panic(err)
	 }

	 // 将签名还原回65个元素的字节数组格式
	 signature, err := hex.DecodeString(signatureStr)
	if err!= nil {
		panic(err)
	}
	 // 3. 通过签名还原公钥
	 pubKey, _, err := eth.ERecovery(message, signature)
	if err!= nil {
		panic(err)
	}
	 // 4. 通过还原的公钥验证签名
	 verify, err := eth.Verify(pubKey, message, signature)
	if err!= nil {
		panic(err)
	}
	if !verify {
		panic(errors.New("无效的签名:"+signatureStr))
	}
	 // 5. 计算发送人地址
	 address := eth.GetEthAddress(pubKey)
	 // 6. 可选：如果知道发送人地址，那可以和参数中的发送人地址进行比对，如果不一致则为错误
	 // 7. 比较区块链中该账户的Nonce，计算是否轮到该笔交易执行，以及执行金额扣减等，此处略过
	 fmt.Println("交易验证通过：发送人", address, "发送", amount, "wei eth给", receipt)
}
