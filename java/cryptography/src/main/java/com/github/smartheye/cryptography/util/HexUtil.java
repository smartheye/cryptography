package com.github.smartheye.cryptography.util;

import org.spongycastle.util.encoders.Hex;

public class HexUtil {

	public static byte[] hex2bytes(String hex) {
		return Hex.decode(hex);
	}
	
	public static String bytes2hex(byte[] bytes) {
		return Hex.toHexString(bytes);
	}
}
