package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class TestUtils {
 
    public static ByteBuffer generateSimpleRawMaterial(int len, int seed1, int seed2) {
        byte[] data = new byte[len];

        seed1 &= 0xff;
        seed2 &= 7;
        int leftshift = seed2;
        int rightshift = (8-seed2);
        for (int i=0; i < len; ++i) {
            byte iRolled = (byte) (((i&0xff) << leftshift) | ((i&0xff) >>> rightshift));
            data[i] = (byte) ((seed1 + (161*(len & 0xff) & 0xff) - iRolled + (i&0xff)));
        }

        return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    }
}
