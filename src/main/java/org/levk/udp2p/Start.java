package org.levk.udp2p;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.levk.udp2p.crypto.SchnorrKey;
import org.levk.udp2p.crypto.SchnorrSig;
import org.levk.udp2p.network.Packet;
import org.levk.udp2p.network.PacketSet;
import org.levk.udp2p.network.peers.Peer;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.levk.udp2p.util.ByteUtils.bytesToBigInteger;
import static org.levk.udp2p.util.HashUtil.blake2;
import static org.levk.udp2p.util.HashUtil.blake2ECC;
import static org.levk.udp2p.util.HashUtil.sha3;

public class Start {
    private static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final ECPoint G = ecSpec.getG();
    private static final BigInteger order = ecSpec.getN();
    private static final BigInteger p = bytesToBigInteger(Hex.decode("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));

    public static void main(String[] args) throws Exception {
        Peer p = new Peer(new byte[20], new byte[4]);
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
