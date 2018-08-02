package org.levk.udp2p.util;

import org.bouncycastle.jcajce.provider.digest.Blake2b;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import java.security.MessageDigest;
import java.util.Arrays;

public class HashUtil {
    public static byte[] blake2(byte[] input) {
        MessageDigest md = new Blake2b.Blake2b256();
        return md.digest(input);
    }

    public static byte[] sha3(byte[] input) {
        MessageDigest md = new Keccak.Digest256();
        return md.digest(input);
    }

    public static byte[] blake2omit12(byte[] input) {
        byte[] hash = blake2(input);
        return Arrays.copyOfRange(hash, 12, hash.length);
    }

    public static byte[] blake2ECC(byte[] input) {
        byte[] hash = blake2(input);
        return Arrays.copyOfRange(hash, 28, hash.length);
    }
}
