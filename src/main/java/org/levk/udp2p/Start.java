package org.levk.udp2p;

import org.bouncycastle.util.encoders.Hex;
import org.levk.udp2p.crypto.SchnorrKey;
import org.levk.udp2p.network.Packet;
import org.levk.udp2p.network.PacketSet;

import java.security.SecureRandom;

import static org.levk.udp2p.util.HashUtil.blake2ECC;
import static org.levk.udp2p.util.HashUtil.sha3;

public class Start {
    public static void main(String[] args) {
        SchnorrKey key = new SchnorrKey();
        byte[] dat = new byte[872];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(dat);

        Packet p = new Packet(Integer.MAX_VALUE, Integer.MAX_VALUE, (byte) 0xFF, Integer.MAX_VALUE, dat, blake2ECC(dat), Integer.MAX_VALUE, key);

        System.out.println(p.getEncoded().length);
        /*
        SchnorrKey key = new SchnorrKey();
        SecureRandom rand = new SecureRandom();
        byte[] data = new byte[873];
        rand.nextBytes(data);
        System.out.println("Data generated.");
        long start = System.currentTimeMillis();
        PacketSet set = new PacketSet(Integer.MAX_VALUE, data, 0xFF013, key);
        System.out.println(System.currentTimeMillis() - start + " ms");

        System.out.println(set.getPackets().get(0).getEncoded().length);
        System.out.println(set.getPackets().size());
        */
    }
}
