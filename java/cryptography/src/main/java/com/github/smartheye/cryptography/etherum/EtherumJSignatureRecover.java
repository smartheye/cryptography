package com.github.smartheye.cryptography.etherum;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.ECKey.ECDSASignature;

import com.github.smartheye.cryptography.etherum.data.Transaction;
import com.github.smartheye.cryptography.util.HexUtil;
import com.github.smartheye.cryptography.util.SHA3Util;
import com.github.smartheye.cryptography.util.AmountUtil;

/**
 * 以太坊从签名中恢复公钥例子
 * 
 * @author He Ye
 *
 */
public class EtherumJSignatureRecover {

	public static final void main(String[] args) throws Exception {
		// 在已知公私钥对的时候，针对消息进行签名
		// 在这里使用的私钥为56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739
		// 公钥为         04 588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271b f6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360
		// 地址为 fa3e91264fd8e76739a36895c1d2bc008c46d425
		// 接受地址为e2f688722675dbdf3a9094927cf0e38d5e714f02
		// 针对签名信息恢复公钥
		// 交易信息
		// 具体内容为转账给e2f688722675dbdf3a9094927cf0e38d5e714f02地址101.23个单位的金额，其中Nonce为1。代表该账户第一笔交易
		// 转账金额：101.23单位
		BigInteger amount = AmountUtil.toUnit(new BigDecimal(101.23).setScale(2, BigDecimal.ROUND_DOWN));
		Transaction transaction = new Transaction(BigInteger.valueOf(1L), "e2f688722675dbdf3a9094927cf0e38d5e714f02",
				amount);
		byte[] transactionJsonBytes = transaction.toJSON().getBytes("UTF-8");
		byte[] messageHash = SHA3Util.keccak256(transactionJsonBytes);


		String signatureHex = "98f9dc270c67d71a255545bf0753375073efc840eceb2a365028cd99abec2c512a8f3d9a3480c1532260cf31cb9881b3dae9d72ea169a66a2a0ca138bb7c19f501";

		byte[] r = HexUtil.hex2bytes(signatureHex.substring(0,64));
		byte[] s = HexUtil.hex2bytes(signatureHex.substring(64,128));
		int v = Integer.parseInt(signatureHex.substring(128));
		ECDSASignature signature = ECDSASignature.fromComponents(r, s, (byte)v);

		// 通过签名恢复公钥
		byte[] pubkeybytes = ECKey.recoverPubBytesFromSignature(v, signature, messageHash);
		System.out.println("恢复出的公钥为:"+HexUtil.bytes2hex(pubkeybytes));
		// 通过公钥再次计算出地址
		ECKey ecKey = ECKey.fromPublicOnly(pubkeybytes);
		System.out.println("恢复出的地址为:"+HexUtil.bytes2hex(ecKey.getAddress())); // fa3e91264fd8e76739a36895c1d2bc008c46d425
	}
}
