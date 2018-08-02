package org.levk.udp2p.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

import static org.levk.udp2p.crypto.SchnorrKey.liftPoint;
import static org.levk.udp2p.util.ByteUtils.bigIntegerToBytes;
import static org.levk.udp2p.util.ByteUtils.bytesToBigInteger;
import static org.levk.udp2p.util.ByteUtils.merge;

public class SchnorrSig {
    private ECPoint R;
    private BigInteger s;

    public SchnorrSig(byte[] data) {
        /* Deserialize signature */
        try {
            this.R = liftPoint(Arrays.copyOfRange(data, 0, 32));
            this.s = bytesToBigInteger(Arrays.copyOfRange(data, 32, 64));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse signature", e);
        }
    }

    public SchnorrSig(ECPoint R, BigInteger s) {
        this.R = R;
        this.s = s;
    }

    public byte[] toBytes() {
        return merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), bigIntegerToBytes(s, 32));
    }
}