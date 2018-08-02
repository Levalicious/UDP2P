package org.levk.udp2p.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/* Taken from EthereumJ */

public class ByteUtils {
    public static final byte[] ZERO_BYTE = {(byte)0x00};
    public static final byte[] ONE_BYTE = {(byte)0x01};
    public static final byte[] EMPTY_BYTE_ARRAY = new byte[1];
    public static final byte[] ZERO_BYTE_ARRAY = new byte[]{0};

    /**
     * The regular {@link BigInteger#toByteArray()} method isn't quite what we often need:
     * it appends a leading zero to indicate that the number is positive and may need padding.
     *
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null)
            return null;
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    /**
     * Cast hex encoded value from byte[] to BigInteger
     * null is parsed like byte[0]
     *
     * @param bb byte array contains the values
     * @return unsigned positive BigInteger value.
     */
    public static BigInteger bytesToBigInteger(byte[] bb) {
        return (bb == null || bb.length == 0) ? BigInteger.ZERO : new BigInteger(1, bb);
    }

    /**
     * @param arrays - arrays to merge
     * @return - merged array
     */
    public static byte[] merge(byte[]... arrays)
    {
        int arrCount = 0;
        int count = 0;
        for (byte[] array: arrays)
        {
            arrCount++;
            count += array.length;
        }

        // Create new array and copy all array contents
        byte[] mergedArray = new byte[count];
        int start = 0;
        for (byte[] array: arrays) {
            System.arraycopy(array, 0, mergedArray, start, array.length);
            start += array.length;
        }
        return mergedArray;
    }

    /**
     * Cast hex encoded value from byte[] to int
     * null is parsed like byte[0]
     *
     * Limited to Integer.MAX_VALUE: 2^32-1 (4 bytes)
     *
     * @param b array contains the values
     * @return unsigned positive int value.
     */
    public static int byteArrayToInt(byte[] b) {
        if (b == null || b.length == 0)
            return 0;
        return new BigInteger(1, b).intValue();
    }

    /**
     * Converts int value into a byte array.
     *
     * @param val - int value to convert
     * @return <code>byte[]</code> of length 4, representing the int value
     */
    public static byte[] intToBytes(int val){
        return ByteBuffer.allocate(Integer.BYTES).putInt(val).array();
    }
}
