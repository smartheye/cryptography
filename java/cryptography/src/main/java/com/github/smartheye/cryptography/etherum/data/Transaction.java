package com.github.smartheye.cryptography.etherum.data;

import java.io.Serializable;
import java.math.BigInteger;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;

/**
 * 交易结构对
 * 仿照以太坊做1对1转账。
 * 由于在此没有矿工费用
 * 所以没有下列变量
 * <code>
 * Price
 * GasLimit
 * </code>
 * 参考
 * https//github.com/ethereum/go-ethereum/core/types/transaction.go
 * @author He Ye
 */
public class Transaction implements Serializable {

	private static final long serialVersionUID = -4723659096522932149L;

	/**
	 * 计数器，从1开始严格递增
	 */
	@JSONField(ordinal = 0)
	private BigInteger accountNonce;

	/**
	 * 收款人地址
	 */
	@JSONField(ordinal = 1)
	private String receipt;

	/**
	 * 金额 金额是10^18=1个金额单位，最小金额单位为微 注意没有小数
	 */
	@JSONField(ordinal = 2)
	private BigInteger amount;

	/**
	 * Base58编码的附加参数
	 */
	@JSONField(ordinal = 3)
	private String payload;

	public Transaction() {

	}
	
	public Transaction(BigInteger accountNonce, String receipt, BigInteger amount) {
		super();
		this.accountNonce = accountNonce;
		this.receipt = receipt;
		this.amount = amount;
		this.payload = null;
	}

	public Transaction(BigInteger accountNonce, String receipt, BigInteger amount, String payload) {
		super();
		this.accountNonce = accountNonce;
		this.receipt = receipt;
		this.amount = amount;
		this.payload = payload;
	}

	public BigInteger getAccountNonce() {
		return accountNonce;
	}

	public void setAccountNonce(BigInteger accountNonce) {
		this.accountNonce = accountNonce;
	}

	public String getReceipt() {
		return receipt;
	}

	public void setReceipt(String receipt) {
		this.receipt = receipt;
	}

	public BigInteger getAmount() {
		return amount;
	}

	public void setAmount(BigInteger amount) {
		this.amount = amount;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}

	@Override
	public String toString() {
		return "Transaction [accountNonce=" + accountNonce + ", receipt=" + receipt + ", amount=" + amount
				+ ", payload=" + payload + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((accountNonce == null) ? 0 : accountNonce.hashCode());
		result = prime * result + ((amount == null) ? 0 : amount.hashCode());
		result = prime * result + ((payload == null) ? 0 : payload.hashCode());
		result = prime * result + ((receipt == null) ? 0 : receipt.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Transaction other = (Transaction) obj;
		if (accountNonce == null) {
			if (other.accountNonce != null)
				return false;
		} else if (!accountNonce.equals(other.accountNonce))
			return false;
		if (amount == null) {
			if (other.amount != null)
				return false;
		} else if (!amount.equals(other.amount))
			return false;
		if (payload == null) {
			if (other.payload != null)
				return false;
		} else if (!payload.equals(other.payload))
			return false;
		if (receipt == null) {
			if (other.receipt != null)
				return false;
		} else if (!receipt.equals(other.receipt))
			return false;
		return true;
	}

	/**
	 * 输出成JSON格式
	 * @return JSON格式
	 */
	public String toJSON() {
		if (this.accountNonce.signum() <= 0) {
			throw new IllegalStateException("AccountNonce必须大于0");
		}
		if (this.amount.signum() <= 0) {
			throw new IllegalStateException("Amount必须大于0");
		}
		String payloadCopy = null;
		if (payload != null && payload.length() > 0) {
			payloadCopy = payload;
		}
		Transaction copy = new Transaction(this.accountNonce, this.receipt, this.amount, payloadCopy);
		// payload为null或者空文字的时候不输出
		return JSON.toJSONString(copy);
	}
}
