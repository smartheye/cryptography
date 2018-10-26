package com.github.smartheye.cryptography.etherum;

import java.math.BigInteger;

import org.ethereum.crypto.ECKey;
import org.spongycastle.math.ec.ECPoint;

import com.github.smartheye.cryptography.util.HexUtil;

/**
 * 以太坊公私钥生成例子
 * 
 * @author He Ye
 *
 */
public class EtherumJKeyMaker {

	public static void main(String[] args) throws Exception {
		System.out.println("01： 随机生成一个私钥");
		ECKey eckey = new ECKey();
		String privateKeyString = getEcKeyPrivateKeyHex(eckey);
		// 输出64个字符的16进制私钥，即256bit私钥
		System.out.println("随机生成的私钥为：" + privateKeyString);// 56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739
		String publicPointUnCompressedHex = getEcKeyPublicPointHex(eckey, false);
		System.out.println("随机生成的私钥对应的公钥（非压缩）为：" + publicPointUnCompressedHex); // 04588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271bf6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360

		String publicPointCompressedHex = getEcKeyPublicPointHex(eckey, true);
		System.out.println("随机生成的私钥对应的公钥（压缩）为：" + publicPointCompressedHex); // 02588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271b

		// 从私钥恢复出ECKey
		eckey = ECKey
				.fromPrivate(HexUtil.hex2bytes("56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739"));
		publicPointUnCompressedHex = getEcKeyPublicPointHex(eckey, false);
		System.out.println("02： 恢复私钥，私钥为56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739");
		System.out.println("恢复私钥对应的公钥（非压缩）为：" + publicPointUnCompressedHex); // 04588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271bf6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360
		publicPointCompressedHex = getEcKeyPublicPointHex(eckey, true);
		System.out.println("恢复私钥对应的公钥（压缩）为：" + publicPointCompressedHex); // 02588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271b
		System.out.println("恢复私钥对应的地址为：" + HexUtil.bytes2hex(eckey.getAddress())); // fa3e91264fd8e76739a36895c1d2bc008c46d425

		System.out.println("03： 通过公式计算是否公私钥匹配。使用的私钥为56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739");
		// 验证公私钥有效性
		// 公式：PubKey = k G
		// G是基点(非压缩格式：04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B
		// 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F
		// FB10D4B8）
		ECPoint g = ECKey.CURVE_SPEC.getG();
		// 获取公钥
		ECPoint pubKey = g.multiply(new BigInteger(1,
				HexUtil.hex2bytes("56255a5c3889c7201b03bc2bd8daa02f10ce21b028c9820295c48f7dc0c3e739")));

		System.out.println("有效性计算得出公钥为："+HexUtil.bytes2hex(pubKey.getEncoded(false))); // 04588a628b0b8363bd40990d3a090045491a8e870e66a70c720437a1400bdc271bf6a89659430134acae1194cd4eb6754ba2df56e0325aac07dcddfbbb3ed80360


	}

	/**
	 * 从EcKey中获取私钥。 私钥是一个256bit的数字。即64个字符的16进制数，或者32个byte的数组。 
	 * <p>
	 * 换算关系：1hex=4bit,
	 * 1byte=8bit
	 * </p>
	 * @return 16进制编码的私钥
	 */
	public static String getEcKeyPrivateKeyHex(ECKey eckey) {
		byte[] privateKeyBytes = eckey.getPrivKeyBytes();
		return HexUtil.bytes2hex(privateKeyBytes);
	}

	/**
	 * 公钥是一个点P(x,y），其中x和y都是256bit的数字。 将x和y拼在一起，就是公钥的16进制表示 但是由于公式是y^2 =
	 * x^3+7，所以只要知道x就可以算出y 在这里我们只要保留x，以及y的奇偶性，就可以通过推算知道y。
	 * 为了区分到底是压缩公钥还是非压缩公钥，比特币规定通过前缀02,03,04来区分 比特币规定前缀04是用来区分非压缩格式公钥
	 * 压缩格式公钥是以02或者03开头，如果y为偶数，则压缩公钥的前缀为02，如果y为奇数，则压缩公钥的前缀为03
	 * 
	 * <p>
	 * 非压缩公钥
	 * </p>
	 * <p>
	 * 非压缩公钥就是简单的把x和y拼在一起后，加上前缀04。
	 * 例如私钥为7ce1e629dc56530761e279771980cc76b765690e68bc475aa977840360f0720d的
	 * 公钥是04903f7733f0b1dd08f6214881b2b65b709b74030961e4890b24e9bead30bc72ccf9e4b69330c7e617321138c1f5a761f82abb8a95144c44794bad1a7e6187f96d
	 * 其中x是903f7733f0b1dd08f6214881b2b65b709b74030961e4890b24e9bead30bc72cc
	 * y是f9e4b69330c7e617321138c1f5a761f82abb8a95144c44794bad1a7e6187f96d
	 * </p>
	 * 
	 * <p>
	 * 压缩公钥
	 * </p>
	 * <p>
	 * 压缩公钥就是简单的把x拿出来，根据y的奇偶性加上前缀02或者03。
	 * </p>
	 * 
	 * @param eckey
	 * @param compressed 压缩和非压缩
	 * @return
	 */
	public static String getEcKeyPublicPointHex(ECKey eckey, boolean compressed) {
		byte[] publicKeyBytes = eckey.getPubKeyPoint().getEncoded(compressed);
		return HexUtil.bytes2hex(publicKeyBytes);
	}
}
