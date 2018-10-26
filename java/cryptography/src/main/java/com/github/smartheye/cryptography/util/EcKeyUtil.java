package com.github.smartheye.cryptography.util;

import org.ethereum.crypto.ECKey;

public class EcKeyUtil {

	public static String getEcKeyPrivateKeyHex(ECKey eckey) {
		byte[] privateKeyBytes = eckey.getPrivKeyBytes();
		return HexUtil.bytes2hex(privateKeyBytes);
	}

	public static String getEcKeyPublicPointHex(ECKey eckey, boolean compressed) {
		byte[] publicKeyBytes = eckey.getPubKeyPoint().getEncoded(compressed);
		return HexUtil.bytes2hex(publicKeyBytes);
	}
}
