package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

public final class XoodooStateHolder implements StateSupplier, StateConsumer {
    private ByteBuffer state;

    public static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0).order(ByteOrder.LITTLE_ENDIAN);

    public static final byte[] ZERO_STATE_BYTES = new byte[48];
    public static final int[] ZERO_STATE_INTS = new int[12];

    public static ByteBuffer createStateBuffer() {
        return ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN);
    }

    private XoodooStateHolder(ByteBuffer stateBuffer) {
        this.state = stateBuffer;
    }

    public static XoodooStateHolder create() {
        return new XoodooStateHolder(createStateBuffer());
    }

    public static XoodooStateHolder from(final ByteBuffer stateBuffer) {
        return new XoodooStateHolder(stateBuffer);
    }

    public static void rollc(int[] rollstate) {
        final int t0 = rollstate[0];
        final int b0 = rollstate[1];
        final int b1 = rollstate[2];

        final int b2 = rollstate[3];
        final int t4 = rollstate[4];
        final int b3 = t0 ^ (t0 << 13) ^ ((t4 << 3) | (t4 >>> 29));

        rollstate[0] = t4;
        rollstate[1] = rollstate[5];
        rollstate[2] = rollstate[6];
        rollstate[3] = rollstate[7];
        rollstate[4] = rollstate[8];
        rollstate[5] = rollstate[9];
        rollstate[6] = rollstate[10];
        rollstate[7] = rollstate[11];

        rollstate[8] = b0;
        rollstate[9] = b1;
        rollstate[10] = b2;
        rollstate[11] = b3;
    }

    public static void rolle(int[] rollstate) {
        final int t0 = rollstate[0];
        final int b0 = rollstate[1];
        final int b1 = rollstate[2];
        final int b2 = rollstate[3];
        final int t4 = rollstate[4];
        final int t8 = rollstate[8];
        final int b3 = ((t0 << 5) | (t0 >>> 27)) ^ ((t4 << 13) | (t4 >>> 19))  ^ (t8 & t4) ^ 7;

        rollstate[0] = t4;
        rollstate[1] = rollstate[5];
        rollstate[2] = rollstate[6];
        rollstate[3] = rollstate[7];
        rollstate[4] = rollstate[8];
        rollstate[5] = rollstate[9];
        rollstate[6] = rollstate[10];
        rollstate[7] = rollstate[11];

        rollstate[8] = b0;
        rollstate[9] = b1;
        rollstate[10] = b2;
        rollstate[11] = b3;
    }

    public void setByteBuffer(ByteBuffer buffer) {
        this.state = buffer;
    }

    public ByteBuffer getByteBuffer() {
        return state;
    }

    public int[] getState() {
        int[] rv = new int[12];
        for (int i=0; i < 12; ++i) {
            rv[i] = get(i);
        }
        return rv;
    }

    @Override
    public StateConsumer put(int offset, int value) {
        state.putInt(offset << 2, value);

        return this;
    }

    @Override
    public int get(int offset) {
        return state.getInt(offset << 2);
    }

    void squeeze(ByteBuffer out, int pos, int stateFrom, int stateTo) {
        this.state.position(stateFrom);
        this.state.get(out.array(), pos, (stateTo-stateFrom));
    }

    void clear(int stateFrom, int stateTo) {
        System.arraycopy(ZERO_STATE_BYTES, 0, this.state.array(), stateFrom, (stateTo-stateFrom));
    }

    boolean isEqual(ByteBuffer data, int offset, int stateFrom, int stateTo) {
        int len = stateTo - stateFrom;
        long cmp = 0L;
        while (len >= 8) {
            cmp |= this.state.getLong(stateFrom) ^ data.getLong(offset);
            offset += 8;
            len -= 8;
            stateFrom += 8;
        }
        if (len >= 4) {
            cmp |= (this.state.getInt(stateFrom) ^ data.getInt(offset));
            offset += 4;
            len -= 4;
            stateFrom += 4;
        }
        if (len >= 2) {
            cmp |= (this.state.getShort(stateFrom) ^ data.getShort(offset));
            offset += 2;
            len -= 2;
            stateFrom += 2;
        }
        if (len > 0) {
            cmp |=  (this.state.get(stateFrom) ^ data.get(offset));
        }

        return cmp == 0L;
    }

    void absorbByte(byte val, int offset) {
        this.state.put(offset, (byte) (val ^ this.state.get(offset)));
    }


    void duplexCrypt(ByteBuffer in, ByteBuffer out, int stateFrom, int stateTo, boolean decrypt) {
        int len = stateTo - stateFrom;

        while (len >= 8) {
            long nextIn = in.getLong();
            long val = this.state.getLong(stateFrom) ;
            long nextOut = val ^ nextIn;
            out.putLong(nextOut);
            this.state.putLong(stateFrom, decrypt ? val ^ nextOut : val ^ nextIn);
            stateFrom += 8;
            len -= 8;
        }

        if (len >= 4) {
            int nextIn = in.getInt();
            int val = this.state.getInt(stateFrom) ;
            int nextOut = val ^ nextIn;
            out.putInt(nextOut);
            this.state.putInt(stateFrom, decrypt ? val ^ nextOut : val ^ nextIn);
            stateFrom += 4;
            len -= 4;
        }

        if (len >= 2) {
            short nextIn = in.getShort();
            short val = this.state.getShort(stateFrom) ;
            short nextOut = (short) (val ^ nextIn);
            out.putShort(nextOut);
            this.state.putShort(stateFrom, (short) (decrypt ? val ^ nextOut : val ^ nextIn));
            stateFrom += 2;
            len -= 2;
        }

        if (len > 0) {
            byte nextIn = in.get();
            byte state = this.state.get(stateFrom) ;
            byte nextOut = (byte) (state ^ nextIn);
            out.put(nextOut);
            this.state.put(stateFrom, (byte) (decrypt ? state ^ nextOut : state ^ nextIn));
        }
    }


    void absorb(ByteBuffer data, int offset, int stateFrom, int stateTo) {
        int len = stateTo - stateFrom;

        while (len >= 8) {            
            state.putLong(stateFrom, state.getLong(stateFrom) ^ data.getLong(offset));
            offset += 8;
            stateFrom += 8;
            len -= 8;
        }
        if (len >= 4) {            
            state.putInt(stateFrom, state.getInt(stateFrom) ^ data.getInt(offset));
            offset += 4;
            stateFrom += 4;
            len -= 4;
        }

        if (len >= 2) {            
            state.putShort(stateFrom, (short) (state.getShort(stateFrom) ^ data.getShort(offset)));
            offset += 2;
            stateFrom += 2;
            len -= 2;
        }

        if (len > 0) {
            state.put(stateFrom, (byte) (state.get(stateFrom) ^ data.get(offset)));
        }
    }
}