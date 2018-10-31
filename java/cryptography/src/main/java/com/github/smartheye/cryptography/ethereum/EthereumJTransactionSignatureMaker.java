package com.github.smartheye.cryptography.ethereum;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Hex;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECKey;

import com.github.smartheye.cryptography.util.HexUtil;

public class EthereumJTransactionSignatureMaker {
    private static final BigInteger DEFAULT_GAS_PRICE = new BigInteger("10000000000000");
    private static final BigInteger DEFAULT_BALANCE_GAS = new BigInteger("21000");
	public static void main(String[] args) {

		ECKey eckey = ECKey.fromPrivate(HexUtil.hex2bytes("d3db87c8daf75d8f2bbea9b646175b826f463e01674ad56b5757249f6e50f3cd"));
		String address = HexUtil.bytes2hex(eckey.getAddress());
		System.out.println("地址："+address);
		Transaction transaction = Transaction.create("fa3e91264fd8e76739a36895c1d2bc008c46d425", BigInteger.ONE, BigInteger.ONE, DEFAULT_GAS_PRICE, DEFAULT_BALANCE_GAS, new Integer(4));
		transaction.sign(eckey);
		System.out.println("编码："+Hex.encodeHexString(transaction.getRawHash()));
		System.out.println("内容："+transaction.toString());
	}

}
