package org.levk.udp2p.network.peers;

import org.levk.udp2p.serialization.TRENC;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;

import static org.bouncycastle.pqc.math.linearalgebra.ByteUtils.xor;

public class PeerSet {
    private int peerCount;

    private int k;
    private Peer[][] buckets;
    public byte[] nodeAddress;

    public PeerSet(byte[] nodeAddress, int k) {
        this.nodeAddress = nodeAddress;
        peerCount = 0;
        this.k = k;

        buckets = new Peer[160][k];
    }

    public boolean hasSpace(Peer p) {
        int bucketIndex = calcDist(nodeAddress, p.getAddress()).indexOf('1');

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (buckets[bucketIndex][i] == null) {
                    return true;
                }
            }
        } else {
            throw new RuntimeException("Attempted to check node against it's own peerset.");
        }

        return false;
    }

    public void add(Peer p) {
        int bucketIndex = calcDist(nodeAddress, p.getAddress()).indexOf('1');

        if (contains(bucketIndex, p.getAddress())) return;

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (buckets[bucketIndex][i] == null) {
                    buckets[bucketIndex][i] = p;
                    peerCount++;
                    return;
                }
            }
        } else {
            throw new RuntimeException("Attempted to add node to it's own peerset.");
        }
    }

    public void remove(byte[] address) {
        int bucketIndex = calcDist(nodeAddress, address).indexOf('1');

        if (!contains(bucketIndex, address)) return;

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (Arrays.equals(address, buckets[bucketIndex][i].getAddress())) {
                    buckets[bucketIndex][i] = null;
                    peerCount--;
                    return;
                }
            }
        } else {
            throw new RuntimeException("Attempted to remove node from it's own peerset.");
        }

    }

    public Peer getPeer(byte[] address) throws PeerNotFoundException {
        int bucketIndex = calcDist(nodeAddress, address).indexOf('1');

        if (!contains(bucketIndex, address)) throw new PeerNotFoundException();

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (Arrays.equals(address, buckets[bucketIndex][i].getAddress())) {
                    return buckets[bucketIndex][i];
                }
            }
        } else {
            throw new RuntimeException("Attempted to get node from it's own peerset.");
        }

        return null;
    }

    public void trimAllBuckets() {
        for (int i = 0; i < 160; i++) {
            trimBucket(i);
        }
    }

    public void trimBucket(int bucketIndex) {
        for (int i = 0; i < k; i++) {
            if (buckets[bucketIndex][i].toDelete()) {
                buckets[bucketIndex][i] = null;
                peerCount--;
            }
        }
    }

    public List<Peer> getAllPeers() {
        List<Peer> out = new ArrayList<>();

        for (int i = 0; i < 160; i++) {
            for (int j = 0; j < k; j++) {
                if (buckets[i][j] != null) {
                    out.add(buckets[i][j]);
                }
            }
        }

        return out;
    }

    public List<Peer> toRefresh() {
        List<Peer> out = new ArrayList<>();

        for (int i = 0; i < 160; i++) {
            out.addAll(toRefreshBucket(i));
        }

        return out;
    }

    public List<Peer> toRefreshBucket(int bucketIndex) {
        List<Peer> out = new ArrayList<>();

        for (int i = 0; i < k; i++) {
            if (buckets[bucketIndex][i].isOld()) {
                out.add(buckets[bucketIndex][i]);
            }
        }

        return out;
    }

    public synchronized void witness(byte[] address) {
        int bucketIndex = calcDist(nodeAddress, address).indexOf('1');

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (Arrays.equals(address, buckets[bucketIndex][i].getAddress())) {
                    buckets[bucketIndex][i].witness();
                }
            }
        } else {
            throw new RuntimeException("Attempted to witness node in it's own peerset.");
        }
    }

    public boolean contains(int bucketIndex, byte[] address) {
        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (Arrays.equals(address, buckets[bucketIndex][i].getAddress())) {
                    return true;
                }
            }
        }

        return false;
    }

    /* Repeated because the less often calcdist needs to be run the better */
    public boolean contains(byte[] address) {
        int bucketIndex = calcDist(nodeAddress, address).indexOf('1');

        if (bucketIndex >= 0) {
            for (int i = 0; i < k; i++) {
                if (Arrays.equals(address, buckets[bucketIndex][i].getAddress())) {
                    return true;
                }
            }
        }

        return false;
    }

    public Peer getRandom() {
        SecureRandom rand = new SecureRandom();

        Peer temp = null;

        while (temp == null) {
            int i = rand.nextInt(160);

            if (bucketContainsPeers(i)) {
                for (int j = 0; j < k; j++) {
                    if (buckets[i][j] != null) {
                        temp = buckets[i][j];
                    }
                }
            }
        }

        return temp;
    }

    public boolean bucketContainsPeers(int bucketIndex) {
        for (int i = 0; i < k; i++) {
            if (buckets[bucketIndex][i] != null) return true;
        }

        return false;
    }

    public static String calcDist(byte[] from, byte[] to) {
        return fromBitSet(fromByteArray(xor(from, to)));
    }

    public static BitSet fromByteArray(byte[] bytes) {
        BitSet bits = new BitSet();
        for (int i = 0; i < bytes.length * 8; i++) {
            if ((bytes[bytes.length - i / 8 - 1] & (1 << (i % 8))) > 0) {
                bits.set(i);
            }
        }
        return bits;
    }

    public static String fromBitSet(BitSet set) {
        final StringBuilder buffer = new StringBuilder(set.length());
        IntStream.range(0, set.length()).mapToObj(i -> set.get(i) ? '1' : '0').forEach(buffer::append);
        String temp = buffer.reverse().toString();
        while(temp.length() < 256) {
            temp = 0 + temp;
        }

        return temp;
    }

    public byte[] getEncoded() {
        byte[][] toEncode = new byte[peerCount][];

        int encoded = 0;
        for (int i = 0; i < 160; i++) {
            for (int j = 0; j < k; j++) {
                if (buckets[i][j] != null) {
                    toEncode[encoded] = buckets[i][j].getEncoded();
                    encoded++;
                }
            }
        }

        return TRENC.encode(toEncode);
    }

    public byte[] getSubset(int num) {
        Set<byte[]> set = new HashSet<>();

        for (int i = 0; i < num; i++) {
            /* TODO: getRandom is gonna be hella slow & has a terrible O() complexity. Fix. */
            Peer temp = getRandom();

            if (temp != null) {
                set.add(temp.getEncoded());
            }
        }

        byte[][] toEncode = new byte[set.size()][];

        int encoded = 0;
        for (byte[] peer : set) {
            toEncode[encoded] = peer;
            encoded++;
        }

        return TRENC.encode(toEncode);
    }
}
