package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

enum XoofffPhase {
    READY,
    COMPRESS,
    BEGIN_EXPAND,
    EXPAND,
}

public final class Xoofff {
    private boolean xooffiee;
    private XoofffPhase phase;

    private XoodooStateHolder ioBuffer;

    private int[] compressedState;
    private int[] rollingKeystate;
    private int[] rollingYState;

    public Xoofff() {

    }

    public Xoofff(byte[] key, int keyBitlen, boolean xooffiee) {
        init(key, keyBitlen, xooffiee);
    }

    void init(byte[] key, int keyBitlen, boolean xooffiee) {
        this.xooffiee = xooffiee;
        if (((keyBitlen + 7)>>> 3) != key.length || keyBitlen > 383) {
            throw new RuntimeException("Invalid key");
        }
        if (this.compressedState != null) {
            System.arraycopy(XoodooStateHolder.ZERO_STATE_INTS, 0, this.compressedState, 0,12);
        }
        if (this.rollingKeystate == null) {
            this.rollingKeystate = new int[12];
        }
        Xoodoo.permuteAndSet(new
            PaddedBlockReader(ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN), XoodooStateHolder.ZERO_STATE_INTS, (byte) 0, 0, keyBitlen),
            this.rollingKeystate, 6);

        this.phase = XoofffPhase.READY;
    }

    void compress(ByteBuffer input, byte frameByte, int frameBits, long bitlen) {
        if (this.compressedState == null) {
            this.compressedState = new int[12];
        }
        ByteOrder inorder = input.order();
        if (inorder != ByteOrder.LITTLE_ENDIAN) {
            input.order(ByteOrder.LITTLE_ENDIAN);
        }

        this.phase = XoofffPhase.COMPRESS;
        long remaining = bitlen;

        input.mark();

        if (remaining >= 384)  {
            FullBlockReader reader = new FullBlockReader(input, this.rollingKeystate);
            do {
                Xoodoo.permuteAndAdd(reader, compressedState, 6);
                remaining -= 384;
                XoodooStateHolder.rollc(this.rollingKeystate);
            } while(remaining >= 384);
        }
        PaddedBlockReader reader = new PaddedBlockReader(input, this.rollingKeystate, frameByte, frameBits, remaining);
        remaining += frameBits + 1;
        do {
            Xoodoo.permuteAndAdd(reader, this.compressedState, 6);
            remaining -= 384;
            XoodooStateHolder.rollc(this.rollingKeystate);
        } while(remaining > 0);
        XoodooStateHolder.rollc(this.rollingKeystate);

        if (inorder != ByteOrder.LITTLE_ENDIAN) {
            input.order(inorder);
        }

        input.reset();
    }

    private void beginExpand() {
        if (this.phase == XoofffPhase.BEGIN_EXPAND || this.phase == XoofffPhase.EXPAND) {
            return;
        }
        if (this.rollingYState == null) {
            this.rollingYState = new int[12];
        }
        if (this.ioBuffer == null) {
            this.ioBuffer = XoodooStateHolder.create();
        }

        if (this.xooffiee) {
            System.arraycopy(this.compressedState, 0, this.rollingYState, 0,12);
        } else {
            Xoodoo.permuteAndSet(compressedState, rollingYState, 6);
        }
        this.phase = XoofffPhase.BEGIN_EXPAND;
    }

    ByteBuffer expand(final ByteBuffer input, ByteBuffer output) {
        if (input != null && output == null) {
            output = ByteBuffer.allocate(input.remaining()).order(ByteOrder.LITTLE_ENDIAN);
        }

        return expand(input, output, ((long) output.remaining()) << 3, 0);
    }

    ByteBuffer expand(final ByteBuffer input, final ByteBuffer output, final long bitlen, int offset) {
        long remaining = bitlen;
        if (remaining <= 0) {
            return output;
        }
        beginExpand();

        ByteOrder inorder = null;
        if (input != null) {
            input.mark();
            inorder = input.order();
            if (inorder != ByteOrder.LITTLE_ENDIAN) {
                input.order(ByteOrder.LITTLE_ENDIAN);
            }
        }
        output.mark();
        ByteOrder outorder = output.order();
        if (outorder != ByteOrder.LITTLE_ENDIAN) {
            output.order(ByteOrder.LITTLE_ENDIAN);
        }

        boolean fillBuffer = (phase == XoofffPhase.BEGIN_EXPAND && offset > 0 && offset < 48)
            || (phase == XoofffPhase.EXPAND && (offset % 48)!=0);

        while(offset >= 48) {
            // roll blocks
            XoodooStateHolder.rolle(this.rollingYState);
            offset -= 48;
        }
        if (fillBuffer) {
            fillExpandBuffer();
        }
        if (offset > 0 && offset < 48)  {
            writeFromBuffer(input, output, remaining, offset);
            offset = 0;
            remaining -= (48-offset)<<3;
            if (remaining > 0) {
                XoodooStateHolder.rolle(this.rollingYState);
            }
        }
        if (remaining >= 384) {
            StateConsumer consumer = input != null ? new FullAddingBlockWriter(input, output, rollingKeystate)
                : new FullBlockWriter(output, rollingKeystate);

            do {
                Xoodoo.permuteAndConsume(
                    this.rollingYState,
                    consumer,
                    6
                );
                remaining -= 384;
                if (remaining > 0) {
                    XoodooStateHolder.rolle(this.rollingYState);
                }
            } while (remaining >= 384);
        }

        if (remaining > 0) {
            fillExpandBuffer();
            writeFromBuffer(input, output, remaining, offset);
        }

        if (input != null) {
            if (inorder != ByteOrder.LITTLE_ENDIAN) {
                input.order(inorder);
            }
            input.reset();
        }

        if (outorder != ByteOrder.LITTLE_ENDIAN) {
            output.order(outorder);
        }
        output.reset();

        this.phase = XoofffPhase.EXPAND;
        return output;
    }

    private void writeFromBuffer(ByteBuffer input, ByteBuffer output, long remaining, int offset) {
        ByteBuffer buffer = ioBuffer.getByteBuffer();
        remaining = Math.min(remaining, (48-offset)<<3);
        if (input != null) {
            while (remaining >= 64) {
                output.putLong(input.getLong() ^ buffer.getLong(offset));
                offset += 8;
                remaining -= 64;
            }
            if (remaining >= 32) {
                output.putInt(input.getInt() ^ buffer.getInt(offset));
                offset += 4;
                remaining -= 32;
            }
            if (remaining >= 16) {
                output.putShort((short) (input.getShort() ^ buffer.getShort(offset)));
                offset += 2;
                remaining -= 16;
            }
            if (remaining > 0) {
                short val = (short) buffer.getShort(offset);
                val &= (short) (0xffff >>> (16-remaining));

                if (remaining > 8) {
                    output.putShort((short) (val ^ input.getShort()));
                } else {
                    output.put((byte) (val ^ input.get()));
                }
            }
        } else {
            while (remaining >= 64) {
                output.putLong(buffer.getLong(offset));
                offset += 8;
                remaining -= 64;
            }
            if (remaining >= 32) {
                output.putInt(buffer.getInt(offset));
                offset += 4;
                remaining -= 32;
            }
            if (remaining >= 16) {
                output.putShort(buffer.getShort(offset));
                offset += 2;
                remaining -= 16;
            }
            if (remaining > 0) {
                short val = buffer.getShort(offset);
                val &= (short) (0xffff >>> (16-remaining));

                if (remaining > 8) {
                    output.putShort(val);
                } else {
                    output.put((byte) val);
                }
            }
        }
    }

    public StateSupplier getExpandBuffer() {
        beginExpand();
        return fillExpandBuffer();
    }

    private StateSupplier fillExpandBuffer() {
        Xoodoo.permuteAndConsume(
            this.rollingYState,
            new BufferWriter(this.ioBuffer, rollingKeystate),
            6
        );
        this.phase = XoofffPhase.EXPAND;
        return this.ioBuffer;
    }

    private static final class BufferWriter implements StateConsumer {
        private final XoodooStateHolder output;
        private final int[] mask;

        public BufferWriter(final XoodooStateHolder output, final int[] mask) {
            this.output = output;
            this.mask = mask;
        }

        @Override
        public StateConsumer put(int offset, int value) {
            output.put(offset, value ^ mask[offset]);
            return this;
        }
    }

    private static final class PaddedBlockReader implements StateSupplier {

        private final ByteBuffer input;
        private final int[] mask;
        private long remaining;
        private int pad;

        public PaddedBlockReader(final ByteBuffer input, final int[] mask, byte frameByte, int frameBits, long inputBitlen) {
            this.input = input;
            this.mask = mask;
            this.remaining = inputBitlen;

            // create pad as frame + simple padding
            this.pad = (frameByte&0x7f) | (1 << (frameBits&7));
        }

        @Override
        public int get(int offset) {
            int rv;
            if (remaining >= 32) {
                rv = input.getInt() ^ mask[offset];

                remaining -= 32;
            } else {
                rv = mask[offset];
                if (remaining > 24) {
                    rv ^= input.getInt();
                } else if (remaining > 16) {
                    rv ^= (input.getShort() & 0xffff) ^ ((input.get() & 0xff) << 16);
                } else if (remaining > 8) {
                    rv ^= (input.getShort() & 0xffff);
                } else if (remaining > 0) {
                    rv ^= (input.get() & 0xff);
                }
                if (pad > 0 && remaining > 0) {
                    rv ^= pad << remaining;
                    pad >>>= (32-remaining);
                    remaining = 0;
                } else if (pad > 0) {
                    rv ^= pad;
                    pad = 0;
                }
            }
            return rv;
        }
    }

    private static final class FullBlockReader implements StateSupplier {

        private final ByteBuffer input;
        private final int[] mask;

        public FullBlockReader(final ByteBuffer input, final int[] mask) {
            this.input = input;
            this.mask = mask;
        }

        @Override
        public int get(int offset) {
            return input.getInt() ^ mask[offset];
        }
    }

    private static final class FullBlockWriter implements StateConsumer {

        private final ByteBuffer output;
        private final int[] rolledKeyState;

        public FullBlockWriter(final ByteBuffer output, final int[] rolledKeyState) {
            this.output = output;
            this.rolledKeyState = rolledKeyState;
        }

        @Override
        public StateConsumer put(int offset, int value) {
            output.putInt(value ^ rolledKeyState[offset]);
            return this;
        }
    }

    private static final class FullAddingBlockWriter implements StateConsumer {

        private final ByteBuffer input;
        private final ByteBuffer output;
        private final int[] rolledKeyState;

        public FullAddingBlockWriter(final ByteBuffer input, final ByteBuffer output, final int[] rolledKeyState) {
            this.input = input;
            this.output = output;
            this.rolledKeyState = rolledKeyState;
        }

        @Override
        public StateConsumer put(int offset, int value) {
            output.putInt(value ^ input.getInt() ^ rolledKeyState[offset]);
            return this;
        }
    }

	public XoofffSavedState saveState() {
        int[] keyBuffer = this.rollingKeystate != null ? new int[12] : null;
        int[] compressedBuffer = this.compressedState != null ? new int[12] : null;

        if (keyBuffer != null) {
            System.arraycopy(this.rollingKeystate, 0, keyBuffer, 0, 12);
        }
        if (compressedBuffer != null) {
            System.arraycopy(this.compressedState, 0, compressedBuffer, 0, 12);
        }

        return new XoofffSavedState(keyBuffer, compressedBuffer, xooffiee);
	}

	public void swapState(XoofffSavedState state) {
        int[] keyBuffer = this.rollingKeystate;
        int[] compressedBuffer = this.compressedState;
        if (state.getCompressedBuffer() == null && this.compressedState != null) {
            state.setCompressedBuffer(new int[12]);
        }
        restoreStateNoCopy(state);

        state.setKeyBuffer(keyBuffer);
        state.setCompressedBuffer(compressedBuffer);
	}

    public void restoreState(XoofffSavedState savedState) {
        if (savedState.getKeyBuffer() != null) {
            this.rollingKeystate = new int[12];
            System.arraycopy(savedState.getKeyBuffer(), 0, this.rollingKeystate, 0, 12);
        } else {
            this.rollingKeystate = null;
        }

        if (savedState.getCompressedBuffer() != null) {
            this.compressedState = new int[12];
            System.arraycopy(savedState.getCompressedBuffer(), 0, this.compressedState, 0, 12);
        } else {
            this.compressedState = null;
        }
    }

	public void restoreStateNoCopy(XoofffSavedState savedState) {
        this.rollingKeystate = savedState.getKeyBuffer();

        if (savedState.getCompressedBuffer() == null && this.compressedState != null) {
            System.arraycopy(XoodooStateHolder.ZERO_STATE_INTS, 0, this.compressedState, 0, 12);
        } else {
            this.compressedState = savedState.getCompressedBuffer();
        }

        this.xooffiee = savedState.isFlag();
        this.phase = XoofffPhase.READY;
	}
}