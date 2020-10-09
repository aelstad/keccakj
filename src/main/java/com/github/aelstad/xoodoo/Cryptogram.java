package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class Cryptogram {
    private final ByteBuffer ciphertext;
    private final ByteBuffer tag;
    private long bitlen;

    public Cryptogram(ByteBuffer ciphertext, ByteBuffer tag, long bitlen) {
        this.ciphertext = ciphertext;
        this.tag = tag;
        this.bitlen = bitlen;
    }

    public Cryptogram(long bitlen) {
        this.ciphertext = ByteBuffer.allocate((int) ((bitlen+7)>>>3)).order(ByteOrder.LITTLE_ENDIAN);
        this.tag = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        this.bitlen = bitlen;
    }

    public ByteBuffer getCiphertext() {
        return ciphertext;
    }

    public ByteBuffer getTag() {
        return tag;
    }

    public long getBitlen() {
        return bitlen;
    }
}
