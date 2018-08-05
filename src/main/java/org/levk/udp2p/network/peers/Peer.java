package org.levk.udp2p.network.peers;

import org.bouncycastle.util.encoders.Hex;
import org.levk.udp2p.serialization.ENCItem;
import org.levk.udp2p.serialization.ENCList;
import org.levk.udp2p.serialization.TRENC;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public class Peer {
    private byte[] encoded;
    private boolean parsed;

    private byte[] address;
    private InetAddress ipAddress;

    private long messagesSeen;
    private boolean isMalicious;
    private long lastSeen;

    public Peer(byte[] encoded) {
        this.encoded = encoded;
        this.parsed = false;

        this.isMalicious = false;
        this.messagesSeen = 0;
    }

    public Peer(byte[] address, byte[] ipAddress) throws UnknownHostException {
        this.address = address;
        this.ipAddress = InetAddress.getByAddress(ipAddress);
        parsed = true;

        this.isMalicious = false;
        this.messagesSeen = 0;
    }

    public synchronized void parse() {
        if (parsed) return;

        try {
            ENCList decPeer = TRENC.decode(encoded);

            if (decPeer.size() > 2) throw new RuntimeException("Too many encoded elements.");
            for (ENCItem e : decPeer) {
                if (e.isList()) throw new RuntimeException("Packet elements should not be lists.");
            }

            this.address = decPeer.get(0).getEncData();
            this.ipAddress = InetAddress.getByAddress(decPeer.get(1).getEncData());

            this.parsed = true;

        } catch (Exception e) {
            throw new RuntimeException("Error on parsing encoding", e);
        }
    }

    public byte[] getEncoded() {
        if (encoded != null) return encoded;

        encoded = TRENC.encode(this.address, this.ipAddress.getAddress());

        return encoded;
    }

    public void witness() {
        this.lastSeen = System.currentTimeMillis();
        this.messagesSeen++;
    }

    public byte[] getAddress() {
        parse();
        return address;
    }

    public InetAddress getIpAddress() {
        parse();
        return ipAddress;
    }

    public boolean isOld() {
        return System.currentTimeMillis() - this.lastSeen > 5000;
    }

    public boolean toDelete() {
        return System.currentTimeMillis() - this.lastSeen > 15000;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Peer)) {
            return false;
        }

        if (!Arrays.equals(((Peer) o).getAddress(), this.address)) {
            return false;
        }

        return ((Peer) o).getIpAddress().equals(this.ipAddress);
    }

    public String toString() {
        return Hex.toHexString(this.address) + " : " + this.ipAddress.toString() + " : " + messagesSeen + "\n";
    }
}
