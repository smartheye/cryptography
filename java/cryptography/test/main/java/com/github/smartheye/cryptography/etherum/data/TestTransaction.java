package com.github.smartheye.cryptography.etherum.data;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

public class TestTransaction{

	/**
	 * 返回一个单位的数值
	 * @return
	 */
	public BigInteger unit(){
		return BigInteger.valueOf(10).pow(18);
	}
	
	@Test
	public void testJson001() {
		String receiptAddress = "1234567890123456789012345678901234567890";
		BigInteger nonce = BigInteger.valueOf(10000000);
		// 金额：10000单位
		BigInteger amount = BigInteger.valueOf(10000L).multiply(unit());
		// null的话不输出
		String payload = null;
		Transaction transaction = new Transaction(nonce, receiptAddress, amount, payload);
		String json = transaction.toJSON();
		
		System.out.println("金额="+amount.toString()); 	// 10000 000 000 000 000 000 000
		System.out.println("JSON="+json);

		assertEquals(json, "{\"accountNonce\":10000000,\"receipt\":\"1234567890123456789012345678901234567890\",\"amount\":10000000000000000000000}");
	}
	
	@Test
	public void testJson002() {
		String receiptAddress = "1234567890123456789012345678901234567890";
		BigInteger nonce = BigInteger.valueOf(10000001);
		// 金额：10000单位
		BigInteger amount = BigInteger.valueOf(10000L).multiply(unit());
		// 空文字的话不输出
		String payload = "";
		Transaction transaction = new Transaction(nonce, receiptAddress, amount, payload);
		String json = transaction.toJSON();
		
		System.out.println("金额="+amount.toString()); 	// 10000 000 000 000 000 000 000
		System.out.println("JSON="+json);

		assertEquals(json, "{\"accountNonce\":10000001,\"receipt\":\"1234567890123456789012345678901234567890\",\"amount\":10000000000000000000000}");
	}
}
