package org.levk.udp2p.serialization;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class TRENC {
    public static final byte[] EMPTY_ELEMENT_TRENC = encode(new byte[1]);

    public static byte[] encode(byte[] data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            byte[] prefix;
            if (data == null) {
                prefix = new byte[]{(byte)0x80};
                out.write(prefix);
            } else {
                prefix = getLengthBytes(data.length);
                out.write(prefix);
                out.write(data);
            }

            return out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encode(byte[]... data) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            outputStream.write((byte)0x00);
            outputStream.write(getLengthBytes(data.length));

            for (byte[] subDat : data) {
                outputStream.write(encode(subDat));
            }

            return outputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ENCList decode(byte[] data) {
        return decode(data, 0);
    }

    /* I really hope this works it looks terrifying to me */
    private static ENCList decode(byte[] data, int startPos) {
        ENCList fin = new ENCList();
        if (data[0] == ((byte)0x80)) {
            fin.add(new ENCItem(new byte[0]));
            return fin;
        }

        /* If the serialized item is a list */
        if (data[0 + startPos] == 0x00) {
            int offset;
            int elCount;

            /*This chunk determines the number of elements in the list */
            /* If the serialized list has less than 128 items */
            if ((data[1 + startPos] & 0xFF) > (0x80 & 0xFF)) {
                /* Loop to deserialize x objects where
                 * x = data[1] % 0x80 */
                offset = 2;
                elCount = (data[1 + startPos] & 0xFF) % (0x80 & 0xFF);
            } else {
                /* If it has more than 128 items */
                /* Because it's not a 1 byte count, no need to & 0xFF or % (0x80 & 0xFF) */
                byte[] elCountBytes = Arrays.copyOfRange(data, 2 + startPos, 2 + data[1 + startPos]);
                offset = 2 + elCountBytes.length;
                elCount = fromBytes(elCountBytes) + 127;
            }

            /* Now that the number of elements is known, we can loop to
             * deserialize each one of them and add them to the ENCList */

            for (int i = 0; i < elCount; i++) {
                ENCItem t = decode(data, offset).get(0);
                offset+= t.getEncData().length + getLengthBytes(t.getEncData().length).length;
                fin.add(t);
            }

            return fin;
        } else {
            /* If the serialized item is not a list */
            int offset;
            int elLength;

            /* If serialized item is less than 128 bytes in length */
            if ((data[0 + startPos] & 0xFF) >= (0x80 & 0xFF)) {
                offset = 1;
                elLength = (data[0 + startPos] & 0xFF) % (0x80 & 0xFF);
            } else {
                /* If the item is greater than 128 bytes */
                byte[] elLengthBytes = Arrays.copyOfRange(data, 1 + startPos, 1 + (data[startPos] & 0xFF) + startPos);
                offset = 1 + elLengthBytes.length;
                elLength = fromBytes(elLengthBytes) + 127;
            }

            System.out.println(elLength);

            /* Now that the element length is known, we can deserialize it & return
             * it in an ENCList containing 1 item. */
            byte[] item = Arrays.copyOfRange(data, offset + startPos, offset + elLength + startPos);
            fin.add(new ENCItem(item));
            return fin;
        }
    }

    public static byte[] getLengthBytes(int i) {
        try {
            if (i < 1) {
                return new byte[]{(byte) 0x80};
            } else {
                byte[] out;

                if (i > 127) {
                    ByteArrayOutputStream outStrem = new ByteArrayOutputStream();
                    outStrem.write((byte)intToBytesNoLeadZeroes(i - 127).length);
                    outStrem.write(intToBytesNoLeadZeroes(i - 127));
                    return outStrem.toByteArray();
                } else {
                    out = new byte[1];
                    out[0] = (byte)(0x80 + i);
                    return out;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static int fromBytes(byte[] in) {
        return Integer.parseUnsignedInt((new ENCItem(in)).toString(), 16);
    }

    public static byte[] intToBytesNoLeadZeroes(int val){

        if (val == 0) return new byte[0];

        int lenght = 0;

        int tmpVal = val;
        while (tmpVal != 0){
            tmpVal = tmpVal >>> 8;
            ++lenght;
        }

        byte[] result = new byte[lenght];

        int index = result.length - 1;
        while(val != 0){

            result[index] = (byte)(val & 0xFF);
            val = val >>> 8;
            index -= 1;
        }

        return result;
    }
}
