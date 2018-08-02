package org.levk.udp2p.network.peers;

public class PeerNotFoundException extends Exception {
    public PeerNotFoundException() {
        super();
    }
    public PeerNotFoundException(String message) {
        super(message);
    }
}
