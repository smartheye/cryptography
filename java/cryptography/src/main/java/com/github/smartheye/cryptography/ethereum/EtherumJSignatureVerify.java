package com.github.smartheye.cryptography.ethereum;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.ECKey.ECDSASignature;

import com.github.smartheye.cryptography.util.HexUtil;
import com.github.smartheye.cryptography.util.SHA3Util;
import com.github.smartheye.cryptography.ethereum.data.Transaction;
import com.github.smartheye.cryptography.util.AmountUtil;

/**
 * 以太坊验签例子
 * 
 * @author He Ye
 *
 */
public class EtherumJSignatureVerify {

	public static final void main(String[] args) throws Exception {
		// 在已知公私钥对的时候，针对消息进行签名
		// 在这里使用的私钥为56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739
		// 公钥为         04 588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271b f6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360
		// 接受地址为e2f688722675dbdf3a9094927cf0e38d5e714f02
		
		// 验证签名需要使用公钥。私钥此时是未知的
		// ECKey eckey = ECKey
		//		.fromPrivate(HexUtil.hex2bytes("56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739"));
		ECKey eckey = ECKey.fromPublicOnly(HexUtil.hex2bytes("04588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271bf6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360"));

		// 交易信息
		// 具体内容为转账给e2f688722675dbdf3a9094927cf0e38d5e714f02地址101.23个单位的金额，其中Nonce为1。代表该账户第一笔交易
		// 转账金额：101.23单位
		BigInteger amount = AmountUtil.toUnit(new BigDecimal(101.23).setScale(2, BigDecimal.ROUND_DOWN));
		Transaction transaction = new Transaction(BigInteger.valueOf(1L), "e2f688722675dbdf3a9094927cf0e38d5e714f02",
				amount);
		byte[] transactionJsonBytes = transaction.toJSON().getBytes("UTF-8");
		byte[] messageHash = SHA3Util.keccak256(transactionJsonBytes);
		
		String signatureHex = "e915038870a7abeeb5578344f7031071998412131594b8122f6ee9bff1bd91865a897449b8816be1a23c4241ffc551d25436f01c248456b265f6ddcc7e14dff501";
		//String signatureHex = "30c878b866b5ab60af32a3a33990a54d5100ae26f1827652e4976fd6423322115a953511beeb8ce854e8c066fbd3b45706c708a78a467e51d2669021e890fab91b";
		// 签名算法
		// 私钥为d，公钥为Q， 消息内容为m，HASH为哈希函数，q为有限域， G为基点
		// 有公式如下
		// Q = dG
		// k： k=SHA-256(d + HASH(m)) 具体参考RFC6979，内容比这个复杂的多
		// r:  r=kG ，其中r是一个点，但是我们只取它的x轴的值，即32位数字设为r
		// s： k*s = (dr + Hash(m)) mod p
		// 1. 验证 :  k*s*G = (drG + Hash(m)*G) mod p  注意此时不知道k
		//    可得 ： r*s = (Q*r + Hash(m)*G) mod p
		//    然后只计算x轴是否匹配
		
		byte[] r = HexUtil.hex2bytes(signatureHex.substring(0,64));
		byte[] s = HexUtil.hex2bytes(signatureHex.substring(64,128));
		int v = Integer.parseInt(signatureHex.substring(128), 16);
		ECDSASignature signature = ECDSASignature.fromComponents(r, s, (byte)v);

		boolean verify = eckey.verify(messageHash, signature);
		System.out.println("01. 验证一个正确签名：验证签名结果="+verify);
		
		String wrongSignatureHex = "88f9dc270c67d71a255545bf0753375073efc840eceb2a365028cd99abec2c512a8f3d9a3480c1532260cf31cb9881b3dae9d72ea169a66a2a0ca138bb7c19f501";
		byte[] wr = HexUtil.hex2bytes(wrongSignatureHex.substring(0,64));
		byte[] ws = HexUtil.hex2bytes(wrongSignatureHex.substring(64,128));
		int wv = Integer.parseInt(wrongSignatureHex.substring(128));
		ECDSASignature wrongSignature = ECDSASignature.fromComponents(wr, ws, (byte)wv);

		System.out.println("02. 验证一个错误签名：验证签名结果="+eckey.verify(messageHash, wrongSignature));
	}
}
