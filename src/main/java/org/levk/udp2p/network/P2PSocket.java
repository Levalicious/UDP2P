package org.levk.udp2p.network;

import org.levk.udp2p.crypto.SchnorrKey;
import org.levk.udp2p.network.peers.Peer;
import org.levk.udp2p.network.peers.PeerNotFoundException;
import org.levk.udp2p.network.peers.PeerSet;
import org.levk.udp2p.serialization.ENCItem;
import org.levk.udp2p.serialization.TRENC;
import org.xerial.snappy.Snappy;

import java.io.IOException;
import java.net.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import static org.levk.udp2p.util.HashUtil.blake2ECC;

public class P2PSocket extends Thread {
    private final SecureRandom rand;

    private Queue<Message> toSend;
    private Queue<Message> toAck;
    private Queue<Message> received;

    private int networkId;
    private int port;
    private boolean running;
    private PeerSet peers;
    private int k;
    private SchnorrKey key;
    private DatagramSocket socket;
    private byte[] buf;

    public P2PSocket(int networkId, SchnorrKey key, int k, int port) throws SocketException {
        rand = new SecureRandom();
        this.toSend = new LinkedList<>();
        this.toAck = new LinkedList<>();
        this.received = new LinkedList<>();
        this.key = key;
        this.k = k;

        this.networkId = networkId;
        this.port = port;

        this.peers = new PeerSet(key.getAddress(), k);

        this.socket = new DatagramSocket(port);
        buf = new byte[1024];
    }

    @Override
    public void run() {
        int i = 0;
        while (running) {
            /* Periodically perform keepalive */
            if (i == 5000) {
                for (Peer p : peers.toRefresh()) {
                    ping(p);
                }
            }

            /* Periodically trim dead peers */
            if (i == 10000) i = 0;
            peers.trimAllBuckets();
            i++;
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                try {
                    /* If not a valid packet, will fail on
                     * parsing or signature validation, in
                     * which case do NOT handle or add to received */
                    Packet p = new Packet(packet.getData());
                    p.parse();

                    if (p.checkSig()) {
                        Message m = new Message(new Peer(p.getSender(), packet.getAddress().getAddress()), p);
                        handleMessage(m);
                    }
                } catch (IOException f) {
                    System.out.println("Compression/Decompression failed.");
                    f.printStackTrace();
                } catch (PeerNotFoundException u) {
                    System.out.println("Handled a message from an unknown peer inappropriately. This should never happen.");
                    u.printStackTrace();
                }



                if (!toSend.isEmpty()) {
                    Message tempMessage = toSend.remove();

                    /* Currently making a network
                     * that's 1 giant network with
                     * virtual subnetworks (networkId)
                     * within it. All networkId's are
                     * treated equally. May move to a
                     * different model at some point,
                     * prioritizing one networkId
                     * over others. */
                    if (awaitAck(tempMessage.getPacket().getPacketType())) {
                        toAck.add(tempMessage);
                    }

                    /* Prepares message for sending */
                    byte[] tempBuf = tempMessage.getPacket().getEncoded();
                    Peer tempPeer = tempMessage.getPeer();

                    /* Creates UDP packet to send */
                    packet = new DatagramPacket(tempBuf, tempBuf.length, tempPeer.getIpAddress(), port);

                    /* Sends packet */
                    socket.send(packet);
                }

                if (!toAck.isEmpty()) {
                    /* Prepares message for sending */
                    byte[] tempBuf = toAck.peek().getPacket().getEncoded();
                    Peer tempPeer = toAck.peek().getPeer();

                    /* Creates UDP packet to send */
                    packet = new DatagramPacket(tempBuf, tempBuf.length, tempPeer.getIpAddress(), port);

                    /* Sends packet */
                    socket.send(packet);
                }
            } catch (IOException n) {
                System.out.println("Socket failed.");
                n.printStackTrace();
                running = false;
            }
        }

        socket.close();
    }

    public boolean awaitAck(int i) {
        switch (i) {
            case 0: return false;
            case 1: return false;
            case 2: return false;
            case 3: return true;
            case 4: return false;
            case 5: return true;
            case 6: return false;
            case 7: return false;
            case 8: return false;
            case 9: return false;
            case 10: return false;
            default: return true;
        }
    }

    public void handleMessage(Message m) throws IOException, PeerNotFoundException {
        /* If packet is a join request (0) */
        if (m.getPacket().getPacketType() == 0) {
            Packet replyPacket;
            if (peers.hasSpace(m.getPeer())) {
                peers.add(m.getPeer());

                /* Reply with yes (2) */
                replyPacket = new Packet(0, 1, randomByte(), 2, new byte[0], blake2ECC(new byte[0]), networkId, key);
            } else {
                /* Reply with no (3) */
                replyPacket = new Packet(0, 1, randomByte(), 3, new byte[0], blake2ECC(new byte[0]), networkId, key);
            }

            Message reply = new Message(m.getPeer(), replyPacket);
            toSend.add(reply);
            return;
        }

        /* If packet is an address request (6) */
        if (m.getPacket().getPacketType() == 6) {
            Packet replyPacket = new Packet(0, 1, randomByte(), 7, this.key.getAddress(), blake2ECC(this.key.getAddress()), networkId, key);
            Message reply = new Message(m.getPeer(), replyPacket);
            toSend.add(reply);
            return;
        }

        /* If packet is an address response (7) */
        if (m.getPacket().getPacketType() == 7) {
            Peer temp = m.getPeer();
            this.connect(temp);
            return;
        }

        /* If not a join request or address request, ignore messages from unknown nodes */
        if (peers.contains(m.getPeer().getAddress())) {
            /* If packet is a leave request (1)
             * Leave requests do not get acked */
            if (m.getPacket().getPacketType() == 1) {
                peers.remove(m.getPeer().getAddress());
                return;
            }

            /* If packet is a yes (2)
             * Automatically request peers
             * upon a successful connection */
            if (m.getPacket().getPacketType() == 2) {
                /* Reply with peer request (4) */
                Packet replyPacket = new Packet(0, 1, randomByte(), 4, new byte[0], blake2ECC(new byte[0]), networkId, key);
                Message reply = new Message(m.getPeer(), replyPacket);
                toSend.add(reply);
                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            /* If packet is a no (3)
             * Remove peer from peerset */
            if (m.getPacket().getPacketType() == 3) {
                /* Remove & reply with ack */
                peers.remove(m.getPeer().getAddress());

                byte[] ackHash = m.getPacket().getPacketECC();
                Packet replyPacket = new Packet(0, 1, randomByte(), 10, ackHash, blake2ECC(ackHash), networkId, key);
                Message reply = new Message(m.getPeer(), replyPacket);
                toSend.add(reply);
                return;
            }

            /* If packet is a peer request (4)
             * serialize the peerset & send */
            if (m.getPacket().getPacketType() == 4) {
                byte[] encodedPeersPreComp = peers.getSubset(31);
                byte[] encodedPeers = Snappy.compress(encodedPeersPreComp);

                /* Reply with peerlist (5) */
                Packet replyPacket = new Packet(0, 1, randomByte(), 5, encodedPeers, blake2ECC(encodedPeers), networkId, key);
                Message reply = new Message(m.getPeer(), replyPacket);
                toSend.add(reply);
                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            /* If packet is a peerset (5)
             * deserialize & attempt to connect */
            if(m.getPacket().getPacketType() == 5) {
                byte[] ackHash = m.getPacket().getPacketECC();
                Packet replyPacket = new Packet(0, 1, randomByte(), 10, ackHash, blake2ECC(ackHash), networkId, key);
                Message reply = new Message(m.getPeer(), replyPacket);
                toSend.add(reply);

                byte[] dat = Snappy.uncompress(m.getPacket().getPayload());
                for (ENCItem i : TRENC.decode(dat)) {
                    Peer temp = new Peer(i.getEncData());
                    if (peers.hasSpace(temp)) {
                        this.connect(temp);
                    }
                }

                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            /* If packet is a ping (8), pong (9) */
            if (m.getPacket().getPacketType() == 8) {
                Packet replyPacket = new Packet(0, 1, randomByte(), 9, new byte[0], blake2ECC(new byte[0]), networkId, key);
                Message reply = new Message(m.getPeer(), replyPacket);
                toSend.add(reply);
                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            if (m.getPacket().getPacketType() == 9) {
                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            /* If packet is an ack */
            if (m.getPacket().getPacketType() == 10) {
                for (Message temp : toAck) {
                    if (Arrays.equals(temp.getPacket().getPacketECC(), m.getPacket().getPayload())) {
                        toAck.remove(temp);
                        return;
                    }
                }

                peers.getPeer(m.getPeer().getAddress()).witness();
                return;
            }

            /* If not a protocol message */
            /* If the packet isn't from a known peer or from the same network, ignore. */
            if (this.networkId == m.getPacket().getNetworkId()) {
                received.add(m);
            }
        }


    }

    public void connect(Peer p) {
        if (peers.hasSpace(p)) {
            Packet joinPacket = new Packet(0, 1, randomByte(), 0, new byte[0], blake2ECC(new byte[0]), networkId, key);
            Message join = new Message(p, joinPacket);
            toSend.add(join);
            peers.add(p);
        }
    }

    public void connect(byte[] ip) {
        try {
            InetAddress addr = InetAddress.getByAddress(ip);
            Packet addrReqPacket = new Packet(0, 1, randomByte(), 6, new byte[0], blake2ECC(new byte[0]), networkId, key);
            Message addrReq = new Message(new Peer(new byte[20]), addrReqPacket);
            toSend.add(addrReq);
        } catch (UnknownHostException u) {
            System.out.println("Connection failed.");
            u.printStackTrace();
        }
    }


    public void send(Message m) {
        toSend.add(m);
    }

    public void broadcast(PacketSet set) {
        for (Packet p : set.getPackets()) {
            broadcast(p);
        }
    }

    public void broadcast(Packet p) {
        for (Peer peer : peers.getAllPeers()) {
            send(new Message(peer, p));
        }
    }

    public void ping(Peer p) {
        Packet pingPacket = new Packet(0, 1, randomByte(), 8, new byte[0], blake2ECC(new byte[0]), networkId, key);
        Message ping = new Message(p, pingPacket);
        toSend.add(ping);
    }

    private byte randomByte() {
        byte[] by = new byte[1];
        rand.nextBytes(by);
        return by[0];
    }
}
