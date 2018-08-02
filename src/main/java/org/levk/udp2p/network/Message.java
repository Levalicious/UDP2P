package org.levk.udp2p.network;

import afu.org.checkerframework.checker.oigj.qual.O;
import org.levk.udp2p.network.peers.Peer;

public class Message {
    private Peer target;
    private Packet message;

    public Message(Peer target, Packet message) {
        this.target = target;
        this.message = message;
    }

    public Peer getPeer() {
        return target;
    }

    public Packet getPacket() {
        return message;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof  Message)) {
            return false;
        }

        if (!(((Message) o).getPacket().getHash() == message.getHash())) {
            return false;
        }

        if (!(((Message) o).getPeer() == target)) {
            return false;
        }

        return true;
    }
}
