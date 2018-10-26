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
 * 以太坊签名例子
 * 
 * @author He Ye
 *
 */
public class EtherumJSignatureMaker {

	public static final void main(String[] args) throws Exception {
		// 在已知公私钥对的时候，针对消息进行签名
		// 在这里使用的私钥为56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739
		// 公钥为         04 588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271b f6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360
		// 接受地址为e2f688722675dbdf3a9094927cf0e38d5e714f02
		ECKey eckey = ECKey
				.fromPrivate(HexUtil.hex2bytes("56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739"));
		//ECKey eckey = new ECKey();

		// 交易信息
		// 具体内容为转账给e2f688722675dbdf3a9094927cf0e38d5e714f02地址101.23个单位的金额，其中Nonce为1。代表该账户第一笔交易
		// 转账金额：101.23单位
		BigInteger amount = AmountUtil.toUnit(new BigDecimal(101.23).setScale(2, BigDecimal.ROUND_DOWN));
		Transaction transaction = new Transaction(BigInteger.valueOf(1L), "e2f688722675dbdf3a9094927cf0e38d5e714f02",
				amount);
		byte[] transactionJsonBytes = transaction.toJSON().getBytes("UTF-8");
		byte[] messageHash = SHA3Util.keccak256(transactionJsonBytes);
		// 签名算法
		// 私钥为d，消息内容为m，HASH为哈希函数，q为有限域， G为基点
		//
		// 1. 选取k： k=SHA-256(d + HASH(m)) 具体参考RFC6979，内容比这个复杂的多
		// 2. 计算r:  r=kG ，其中r是一个点，但是我们只取它的x轴的值，即32位数字设为r
		// 3. 计算s： k*s = (dr + Hash(m)) mod p
		ECDSASignature signature = eckey.sign(messageHash).toCanonicalised();

		BigInteger r = signature.r;
		BigInteger s = signature.s;
		int v = signature.v - 27;

		//String rHexValue = HexUtil.bytes2hex(r.toByteArray()); toByteArray如果为负的话，前面会加00前缀，也就是变成66位
		//String sHexValue = HexUtil.bytes2hex(s.toByteArray());
		// 转化为16进制
		String rHexValue = r.toString(16);
		String sHexValue = s.toString(16);
		System.out.println("r=" + rHexValue + ", r length=" + rHexValue.length());
		System.out.println("s=" + sHexValue + ", s length=" + sHexValue.length());
		System.out.println("v=" + v);

		// 98f9dc270c67d71a255545bf0753375073efc840eceb2a365028cd99abec2c512a8f3d9a3480c1532260cf31cb9881b3dae9d72ea169a66a2a0ca138bb7c19f501
		System.out.println("signature hex=" + signature.toHex() + ", length=" + signature.toHex().length());

		BigInteger k = new BigInteger(1,
				HexUtil.hex2bytes("56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739"));
		System.out.println(k);
		System.out.println(HexUtil.bytes2hex(k.toByteArray()));

	}
}
