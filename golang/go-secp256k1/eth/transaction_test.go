package eth

import (
	"fmt"
	"github.com/issue9/assert"
	"testing"
)

func TestNewEthTransaction001(t *testing.T) {
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	json, err:=transaction.ToJSON()
	assert.Nil(t, err)
	fmt.Println(string(json))
	assert.Equal(t, json, `{"accountNonce":"1","receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":"101230000000000000000"}`)
}

func TestNewEthTransaction002(t *testing.T) {
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	transaction.AccountNonce = nil

	json, err:=transaction.ToJSON()
	assert.Nil(t, err)
	fmt.Println(string(json))
	assert.Equal(t, string(json), `{"accountNonce":null,"receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":"101230000000000000000"}`)
}

func TestNewEthTransaction003(t *testing.T) {
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	transaction.Receipt = nil

	json, err:=transaction.ToJSON()
	assert.Nil(t, err)
	fmt.Println(string(json))
	assert.Equal(t, string(json), `{"accountNonce":"1","receipt":null,"amount":"101230000000000000000"}`)
}

func TestNewEthTransaction004(t *testing.T) {
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	transaction.Amount = nil

	json, err:=transaction.ToJSON()
	assert.Nil(t, err)
	fmt.Println(string(json))
	assert.Equal(t, string(json), `{"accountNonce":"1","receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":null}`)
}

func TestNewEthTransaction005(t *testing.T) {
	var payload = "test"
	var transaction = NewTransaction("1", "e2f688722675dbdf3a9094927cf0e38d5e714f02", "101230000000000000000")
	transaction.Payload= &payload
	json, err:=transaction.ToJSON()
	assert.Nil(t, err)
	fmt.Println(string(json))
	assert.Equal(t, string(json), `{"accountNonce":"1","receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":"101230000000000000000","payload":"test"}`)
}

func TestParseFromJSON001(t *testing.T) {
	var jsonStr = `{"accountNonce":"1","receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":"101230000000000000000","payload":"test"}`
	transaction,err := NewTransactionFromJSON(jsonStr)
	assert.Nil(t, err)
	assert.Equal(t, *transaction.AccountNonce, "1")
	assert.Equal(t, *transaction.Receipt, "e2f688722675dbdf3a9094927cf0e38d5e714f02")
	assert.Equal(t, *transaction.Amount, "101230000000000000000")
	assert.Equal(t, *transaction.Payload, "test")
}

func TestParseFromJSON002(t *testing.T) {
	var jsonStr = `{"accountNonce":"1","receipt":"e2f688722675dbdf3a9094927cf0e38d5e714f02","amount":"101230000000000000000"}`
	transaction,err := NewTransactionFromJSON(jsonStr)
	assert.Nil(t, err)
	assert.Equal(t, *transaction.AccountNonce, "1")
	assert.Equal(t, *transaction.Receipt, "e2f688722675dbdf3a9094927cf0e38d5e714f02")
	assert.Equal(t, *transaction.Amount, "101230000000000000000")
	//assert.Nil(t, transaction.Payload)

}
