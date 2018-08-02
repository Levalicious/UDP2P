package org.levk.udp2p.serialization;

import java.util.Arrays;

public class ENCItem {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private byte[] data;

    public ENCItem(byte[] data) {
        this.data = data;
    }

    public byte[] getEncData() {
        return data;
    }

    public String toString() {
        char[] hexChars = new char[data.length * 2];
        for ( int j = 0; j < data.length; j++ ) {
            int v = data[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ENCItem)) {
            return false;
        }

        if (!Arrays.equals(this.data, ((ENCItem) o).getEncData())) {
            return false;
        }

        return true;
    }

    public boolean isList() {
        if (isEncoded()) {
            if (data[0] == 0x00) return true;
        }

        return false;
    }

    public boolean isEncoded() {
        try {
            TRENC.decode(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
