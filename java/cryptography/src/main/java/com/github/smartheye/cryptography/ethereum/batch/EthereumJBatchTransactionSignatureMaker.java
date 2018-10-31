package com.github.smartheye.cryptography.ethereum.batch;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;

import org.apache.commons.codec.binary.Hex;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.ECKey.ECDSASignature;

import com.github.smartheye.cryptography.ethereum.data.Transaction;
import com.github.smartheye.cryptography.util.AmountUtil;
import com.github.smartheye.cryptography.util.HexUtil;
import com.github.smartheye.cryptography.util.SHA3Util;

public class EthereumJBatchTransactionSignatureMaker {
	public static void main(String[] args) {
		byte[] messageHash = getMessageHash();
		
		int i=0;
		while(i<30000){
			ECKey eckey = new ECKey();
			String privKey = HexUtil.bytes2hex(eckey.getPrivKeyBytes());
			BigInteger privateKeyD = eckey.getPrivKey();
			String pubUncompressKey = HexUtil.bytes2hex(eckey.getPubKeyPoint().getEncoded(false));
			String pubCompressKey = HexUtil.bytes2hex(eckey.getPubKeyPoint().getEncoded(true));
			String address = HexUtil.bytes2hex(eckey.getAddress());
	
			ECDSASignature signature = eckey.sign(messageHash).toCanonicalised();
	
			BigInteger r = signature.r;
			BigInteger s = signature.s;
			int v = signature.v - 27;
			if(v==2) {
				System.out.println(String.format("privateKey=%s \nprivateKey.D=%d \npubUncompressKey=%s \npubKey=%s \naddress=%s", privKey, privateKeyD, pubUncompressKey, pubCompressKey, address));
				System.out.println("signature hex=" + signature.toHex());
				break;
			}
		}
	}

	
	private static byte[] getMessageHash() {
		// 交易信息
		// 具体内容为转账给e2f688722675dbdf3a9094927cf0e38d5e714f02地址101.23个单位的金额，其中Nonce为1。代表该账户第一笔交易
		// 转账金额：101.23单位
		BigInteger amount = AmountUtil.toUnit(new BigDecimal(101.23).setScale(2, BigDecimal.ROUND_DOWN));
		Transaction transaction = new Transaction(BigInteger.valueOf(1L), "e2f688722675dbdf3a9094927cf0e38d5e714f02",
				amount);
		System.out.println("JSON="+transaction.toJSON());
		byte[] transactionJsonBytes;
		try {
			transactionJsonBytes = transaction.toJSON().getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		
		byte[] messageHash = SHA3Util.keccak256(transactionJsonBytes);
		
		return messageHash;
	}
}
