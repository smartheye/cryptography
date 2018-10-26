package com.github.smartheye.cryptography.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.ethereum.crypto.jce.SpongyCastleProvider;

public class SHA3Util {

	public static final byte[] keccak256(byte[] input) {
		MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("ETH-KECCAK-256", SpongyCastleProvider.getInstance());
            digest.update(input);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
	}
}
