package org.levk.udp2p.serialization;

import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

public class TRENCTests {
    public static void main(String[] args) {
        byte[] data = new byte[10];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(data);
        byte[] dat = null;

        byte[] enc = TRENC.encode(data, dat, data);

        System.out.println(Hex.toHexString(enc));
        ENCList list = TRENC.decode(enc);

        System.out.println(Hex.toHexString(list.get(1).getEncData()));
        System.out.println(Hex.toHexString(list.get(2).getEncData()));
    }
}
