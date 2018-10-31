package com.github.smartheye.cryptography.ethereum.batch;

import java.math.BigInteger;

import org.ethereum.crypto.ECKey;

import com.github.smartheye.cryptography.util.HexUtil;

public class EthereumBatchKeyMaker {

	public static void main(String[] args) {
		ECKey eckey = new ECKey();
		String privKey = HexUtil.bytes2hex(eckey.getPrivKeyBytes());
		BigInteger privateKeyD = eckey.getPrivKey();
		String pubUncompressKey = HexUtil.bytes2hex(eckey.getPubKeyPoint().getEncoded(false));
		String pubCompressKey = HexUtil.bytes2hex(eckey.getPubKeyPoint().getEncoded(true));
		String address = HexUtil.bytes2hex(eckey.getAddress());
		System.out.println(String.format("privateKey=%s, privateKey.D=%d, pubUncompressKey=%s, pubKey=%s, address=%s", privKey, privateKeyD, pubUncompressKey, pubCompressKey, address));
	}

}
