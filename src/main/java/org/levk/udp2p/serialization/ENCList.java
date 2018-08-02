package org.levk.udp2p.serialization;

import java.util.ArrayList;

public class ENCList extends ArrayList<ENCItem> {
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ENCList)) {
            return false;
        }

        if (((ENCList) o).size() != this.size()) {
            return false;
        }

        for (int i = 0; i < this.size(); i++) {
            if (!this.get(i).equals(((ENCList) o).get(i))) {
                System.out.println("Byte array " + i + " is different.");
                return false;
            }
        }

        return true;
    }

    public byte[] getEncoded() {
        byte[][] data = new byte[super.size()][];

        for (int i = 0; i < super.size(); i++) {
            data[i] = super.get(i).getEncData();
        }
        return TRENC.encode(data);
    }

    public boolean isList(int i) {
        return super.get(i).isList();
    }

    public ENCList getList(int i) {
        return TRENC.decode(super.get(i).getEncData());
    }

    public byte[] getBytes(int i) {
        return super.get(i).getEncData();
    }
}
