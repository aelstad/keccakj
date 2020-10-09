package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class Xoodyak {
    private XoodooStateHolder state;

    private boolean up;
    private boolean keyed;
    private int absorbRate;
    private int squeezeRate;

    public Xoodyak(byte[] key, byte[] id, byte[] counter) {
        this.up = true;
        this.keyed = false;
        this.absorbRate = 16;
        this.squeezeRate = 16;

        this.state = XoodooStateHolder.create();

        if (key != null) {
            absorbKey(key,  id, counter);
        }
    }

    public void ratchet() {
        checkKeyed();
        this.state.absorbByte((byte) 0x10, 47);
        permute();
        this.state.clear(0, 16);
        this.state.absorbByte((byte) 0x01, 16);
        this.up = false;
    }

    public void absorb(ByteBuffer data) {
        this.absorbAny(data, this.absorbRate, (byte) 0x03);
    }

    public byte[] squeezeNew(int len) {
        byte[] rv = new byte[len];
        this.squeeze(ByteBuffer.wrap(rv).order(ByteOrder.LITTLE_ENDIAN));
        return rv;
    }

    public void squeeze(ByteBuffer buffer) {
        this.squeezeAny(buffer, (byte) 0x40);
    }

    public void squeezeKey(ByteBuffer buffer) {
        this.checkKeyed();
        this.squeezeAny(buffer, (byte) 0x20);
    }

    /**
     * Encrypts [position,limit) of input to an optional output buffer.
     * The current position in the buffers are marked.
     * 
     * @param input Buffer with plaintext
     * @param output - If null, a new buffer is allocated
     * @return Output buffer.
     */
    public ByteBuffer encrypt(ByteBuffer input, ByteBuffer output) {
        this.checkKeyed();

        if (output == null) {
            output = ByteBuffer.allocate(input.limit() - input.position());
        }
        this.crypt(input, output, false);
        return output;
    }

    /**
     * Decrypts [position,limit) of input to an optional output buffer.
     * The current position in the buffers are marked.
     * 
     * @param input Buffer with plaintext
     * @param output - If null, a new buffer is allocated
     * @return Output buffer.
     */
    public ByteBuffer decrypt(ByteBuffer input, ByteBuffer output) {
        this.checkKeyed();
        if (output == null) {
            output = ByteBuffer.allocate(input.limit() - input.position());
        }
        this.crypt(input, output, true);
        return output;
    }

    private void squeezeAny(ByteBuffer data, byte padSqueeze) {
        data.mark();
        ByteOrder order = data.order();
        if (order != ByteOrder.LITTLE_ENDIAN) {
            data.order(ByteOrder.LITTLE_ENDIAN);
        }

        int offset = data.position();
        int limit = data.limit();
        int chunkSize = Math.min(limit - offset, this.squeezeRate);
        if (this.keyed) {
            this.state.absorbByte(padSqueeze, 47);
        }
        permute();
        this.state.squeeze(data, offset, 0, chunkSize);
        offset += chunkSize;
        while (offset < limit) {
            this.state.absorbByte((byte) 0x01, 0);
            permute();
            chunkSize = Math.min(limit - offset, this.squeezeRate);
            this.state.squeeze(data, offset, 0, chunkSize);
            offset += chunkSize;
        }
        this.up = true;

        if (order != ByteOrder.LITTLE_ENDIAN) {
            data.order(order);
        }
        data.reset();
    }


    private void absorbAny(ByteBuffer data, int rate, byte padAbsorb) {
        data.mark();
        ByteOrder order = data.order();
        if (order != ByteOrder.LITTLE_ENDIAN) {
            data.order(ByteOrder.LITTLE_ENDIAN);
        }

        if (!this.up) {
            permute();
        }
        int offset = data.position();
        int limit = data.limit();
        int chunkSize = Math.min(limit - offset, rate);
        this.down(data, offset, chunkSize, padAbsorb);
        offset += chunkSize;
        while(offset < limit) {
            permute();

            chunkSize = Math.min(limit - offset, rate);
            this.state.absorb(data, offset, 0, chunkSize);
            this.state.absorbByte((byte) 0x01, chunkSize);
            offset += chunkSize;
        }

        if (order != ByteOrder.LITTLE_ENDIAN) {
            data.order(order);
        }
        data.reset();
    }

    private void down(ByteBuffer data, int offset, int size, byte pad)  {
        this.state.absorb(data, offset, 0, size);
        this.state.absorbByte((byte) 0x01, size);
        this.state.absorbByte((byte) (this.keyed ? pad : pad & 0x01), 47);
        this.up = false;
    }

    private void checkKeyed() {
        if (!this.keyed) {
            throw new RuntimeException("Operation requires a keyed Xoodyak");
        }
    }

    private void crypt(ByteBuffer input, ByteBuffer output, boolean decrypt) {
        input.mark();
        output.mark();

        ByteOrder inOrder = input.order();
        if (inOrder != ByteOrder.LITTLE_ENDIAN) {
            input.order(ByteOrder.LITTLE_ENDIAN);
        }

        ByteOrder outOrder = output.order();
        if (outOrder != ByteOrder.LITTLE_ENDIAN) {
            output.order(ByteOrder.LITTLE_ENDIAN);
        }

        int offset = input.position();
        int limit = input.limit();

        this.state.absorbByte((byte) 0x80, 47);
        permute();

        int chunkSize = Math.min(limit - offset, this.squeezeRate);
        this.state.duplexCrypt(input, output, 0, chunkSize, decrypt);
        offset += chunkSize;
        this.state.absorbByte((byte)0x01, chunkSize);
        while(offset < limit) {
            chunkSize = Math.min(limit - offset, this.squeezeRate);
            permute();
            this.state.duplexCrypt(input, output, 0, chunkSize, decrypt);
            offset += chunkSize;
            this.state.absorbByte((byte) 0x01, chunkSize);
        }
        this.up = false;

        if (inOrder != ByteOrder.LITTLE_ENDIAN) {
            input.order(inOrder);
        }

        if (outOrder != ByteOrder.LITTLE_ENDIAN) {
            output.order(outOrder);
        }

        output.reset();
        input.reset();
    }

    private void permute() {
        Xoodoo.permuteExternalState(state, state, 12);
    }

    private void absorbKey(byte[] key, byte[] id, byte[] counter) {
        this.keyed = true;
        this.absorbRate = 44;
        this.squeezeRate = 24;
        int idLength = id  != null ? id.length : 0;
        int keypackLength = key.length + idLength + 1;
        ByteBuffer keypack = ByteBuffer.allocate(keypackLength).order(ByteOrder.LITTLE_ENDIAN);
        keypack.put(key);
        if (id != null) {
            keypack.put(id);
        }
        keypack.put((byte) idLength);
        keypack.flip();
        this.absorbAny(keypack, this.absorbRate, (byte) 0x02);
        if (counter != null && counter.length > 0) {
            this.absorbAny(ByteBuffer.wrap(counter).order(ByteOrder.LITTLE_ENDIAN), 1, (byte) 0x00);
        }
    }
}
