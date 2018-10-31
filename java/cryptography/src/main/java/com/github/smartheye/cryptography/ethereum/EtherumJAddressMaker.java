package com.github.smartheye.cryptography.ethereum;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.ethereum.config.SystemProperties;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.jce.SpongyCastleProvider;

import com.github.smartheye.cryptography.util.HexUtil;

/**
 * 以太坊地址生成例子
 * 
 * @author He Ye
 *
 */
public class EtherumJAddressMaker {

	public static final void main(String[] args) {
		// 在已知公私钥对的时候，生成以太坊格式的地址。
		// 公私钥对生成和恢复方法参考EtherumJKeyMaker
		
		ECKey key = new ECKey();
		//String privateKeyHex = EcKeyUtil.getEcKeyPrivateKeyHex(key);
		//String publicKeyHexCompressed = EcKeyUtil.getEcKeyPublicPointHex(key, false);
		
		String address = HexUtil.bytes2hex(key.getAddress());
		System.out.println("使用的SHA256算法为：" + SystemProperties.getDefault().getHash256AlgName());
		System.out.println("1. 调用API获取以太坊地址");
		System.out.println("以太坊地址为：" + address);

		// 手工计算地址
		// 以太坊地址生成算法（和比特币不同）
		// 1. 获取非压缩公钥（65位byte数组）
		// 2. 舍去非压缩公钥（65位byte数组）的第一位，即标志位04
		// 3. 获取剩下的64位byte数组，其中前32位byte是x，后32位byte是y
		// 4. 执行Keccak256哈希算法。得到32位byte数组
		// 5. 舍去前12位，只取后20位byte数组构成地址
		// 6. 将后20位byte数组变成16进制编码的字符串，即40位字符串。
		// 注意：以太坊地址由于上述计算方法的关系，必定是40位字符串，且不区分主网和测试网
		byte[] pubkeybytes = key.getPubKeyPoint().getEncoded(false);
		System.out.println("2. 手工通过公钥计算出以太坊地址");
		System.out.println("手工计算公钥byte数组长度="+pubkeybytes.length);
		
		MessageDigest digest;
		byte[] pubkeySha3bytes;
        try {
            digest = MessageDigest.getInstance("ETH-KECCAK-256", SpongyCastleProvider.getInstance());
            digest.update(Arrays.copyOfRange(pubkeybytes, 1, pubkeybytes.length));
            pubkeySha3bytes = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        System.out.println("手工计算Keccak256(公钥byte数组)后的长度="+pubkeySha3bytes.length);
        byte[] calcedAddressBytes = Arrays.copyOfRange(pubkeySha3bytes, 12, pubkeySha3bytes.length);
        String calcedAddress = HexUtil.bytes2hex(calcedAddressBytes);
		System.out.println("手工计算得出的以太坊地址为：" + calcedAddress);
	}
}
