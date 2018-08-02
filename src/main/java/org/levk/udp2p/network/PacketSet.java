package org.levk.udp2p.network;

import org.levk.udp2p.crypto.SchnorrKey;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.levk.udp2p.util.HashUtil.blake2ECC;

public class PacketSet {
    private static final SecureRandom rand = new SecureRandom();
    private static final int MAX_PACKET_PAYLOAD = 872;

    private int packetType;
    private Packet[] packets;
    private int packetCount = 0;

    private boolean complete;

    public PacketSet(int packetType, byte[] data, int networkId, byte[] privkey) {
        this(packetType, new byte[20], data, networkId, new SchnorrKey(privkey));
    }

    public PacketSet(int packetType, byte[] target, byte[] data, int networkId, byte[] privkey) {
        this(packetType, target, data, networkId, new SchnorrKey(privkey));
    }

    public PacketSet(int packetType, byte[] data, int networkId, SchnorrKey key) {
        this(packetType, new byte[20], data, networkId, key);
    }

    public PacketSet(int packetType, byte[] target, byte[] data, int networkId, SchnorrKey key) {
        byte[] messageHash = blake2ECC(data);

        this.packetType = packetType;

        byte[][] temp = partition(data, MAX_PACKET_PAYLOAD);

        packets = new Packet[temp.length];

        for (int i = 0; i < temp.length; i++) {
            packets[i] = new Packet(i, temp.length, randomByte(), target, packetType, temp[i], messageHash, networkId, key);
            packetCount++;
        }

        complete = true;
    }

    public PacketSet(Packet packet) {
        packets = new Packet[packet.getSetSize()];
        packets[packet.getSetIndex()] = packet;
        packetCount++;
        packetType = packet.getPacketType();

        updateComplete();
    }

    public void add(Packet packet) {
        if (complete) return;

        if (packets[packet.getSetIndex()] == null) {
            packets[packet.getSetIndex()] = packet;
            packetCount++;

            updateComplete();
        }
    }

    public int getSetType() {
        return packetType;
    }

    private void updateComplete() {
        complete = (packetCount == packets.length);
    }

    public boolean isComplete() {
        return complete;
    }

    public List<Packet> getPackets() {
        List<Packet> temp = new ArrayList<>();

        for (int i = 0; i < packets.length; i++) {
            temp.add(packets[i]);
        }

        return temp;
    }

    public Packet getRandom() {
        return packets[rand.nextInt(packets.length)];
    }



    private static byte[][] partition(byte[] in, int partitionSize) {
        int partitionCount =  (int)Math.ceil((double)in.length / (double)partitionSize);

        byte[][] temp = new byte[partitionCount][partitionSize];

        for (int i = 0; i < partitionCount; i++) {
            if (in.length < (partitionSize * (i + 1))) {
                temp[i] = new byte[(in.length - (partitionSize * i))];
            }

            for(int j = 0; (j < partitionSize && (partitionSize * i + j) < in.length); j++) {
                temp[i][j] = in[(partitionSize * i + j)];
            }
        }

        return temp;
    }

    private static byte randomByte() {
        byte[] by = new byte[1];
        rand.nextBytes(by);
        return by[0];
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PacketSet)) return false;

        try {
            for (int i = 0; i < packets.length; i++) {
                if (!packets[i].equals(((PacketSet)o).getPackets().get(i))) return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
