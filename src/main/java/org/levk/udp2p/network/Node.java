package org.levk.udp2p.network;

import org.levk.udp2p.crypto.SchnorrKey;

import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

class Node {
    private P2PSocket socket;
    private SchnorrKey key;

    public Node() {
        try {
            this.key = new SchnorrKey();
            this.socket = new P2PSocket(1, 2, key, 3, 40424);
        } catch (SocketException s) {
            System.out.println("Socket initialization failed.");
            s.printStackTrace();
            System.exit(-1);
        }
    }

    public void connect(String IP) throws UnknownHostException {
        InetAddress ad = InetAddress.getByName(IP);
        socket.connect(ad.getAddress());
    }

    public String getPeers() {
        return socket.getPeers();
    }

}
