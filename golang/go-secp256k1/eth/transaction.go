package eth

import (
	"encoding/json"
	"errors"
)

/*
以太坊交易结构
注意结构定义的交易顺序一定要和其他语言一样
 */
type Transaction struct{
	// Nonce，十进制，必须转化为big.Int
	AccountNonce *string `json:"accountNonce"`
	// 收款人地址
	Receipt *string `json:"receipt"`
	// 金额，十进制，必须转为big.Int
	Amount *string `json:"amount"`
	// 附加参数，可以为空，且空的时候不输出到JSON
	Payload *string `json:"payload,omitempty"`
}

func NewTransaction(accountNonce string, receipt string, amount string) (*Transaction){
	var transaction = &Transaction{}
	transaction.AccountNonce = &accountNonce
	transaction.Receipt = &receipt
	transaction.Amount = &amount
	return transaction
}

func NewTransactionFromJSON(jsonStr string)  (*Transaction, error){
	data:=[]byte(jsonStr)
	var Transaction = &Transaction{}
	err:=json.Unmarshal(data, Transaction)
	return Transaction, err
}

func (t *Transaction) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

func (t *Transaction) ValidCheck() error {
	if t.AccountNonce == nil {
		return errors.New("accountNonce is nil")
	}
	if t.Receipt == nil {
		return errors.New("receipt is nil")
	}
	if t.Amount == nil {
		return errors.New("amount is nil")
	}
	return nil
}