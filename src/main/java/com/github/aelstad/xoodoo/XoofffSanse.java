package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class XoofffSanse {
    private Xoofff xoofff;
    private boolean e;

    public XoofffSanse() {

    }

    public XoofffSanse(byte[] key, int keyBitlen) {
        this.init(key, keyBitlen);
    }

    public XoofffSavedState saveState() {
        XoofffSavedState state = xoofff.saveState();
        state.setFlag(e);
        return state;
    }

    public void swapState(XoofffSavedState state) {
        boolean currentE = this.e;
        boolean savedE = state.isFlag();
        state.setFlag(false);
        xoofff.swapState(state);
        state.setFlag(currentE);
        this.e = savedE;
    }

    public void restoreStateNoCopy(XoofffSavedState state) {
        this.e = state.isFlag();
        state.setFlag(false);
        xoofff.restoreStateNoCopy(state);
    }

    public void restoreState(XoofffSavedState state) {
        this.e = state.isFlag();
        state.setFlag(false);
        xoofff.restoreState(state);
    }

    public void init(byte[] key, int keyBitlen) {
        if (this.xoofff == null)
            this.xoofff = new Xoofff();

        this.xoofff.init(key, keyBitlen, false);
        this.e = false;
    }

    public Cryptogram wrap(byte[] metadata, byte[] plaintext) {
        return wrap(metadata != null ? ByteBuffer.wrap(metadata).order(ByteOrder.LITTLE_ENDIAN) : null,
            plaintext != null ? ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN) : null,
            metadata != null ? ((long) metadata.length) << 3 : 0,
            plaintext != null ? ((long) plaintext.length) << 3 : 0,
            null);
    }

    public Cryptogram wrap(ByteBuffer metadata, ByteBuffer plaintext, long metadataBitlen, long plaintextBitlen, Cryptogram cryptogram) {
        if (((metadataBitlen + 7) >>> 3) != (metadata != null ? metadata.remaining() : 0)) {
            throw new RuntimeException("Invalid metadata length");
        }

        if (((plaintextBitlen + 7) >>> 3) != (plaintext != null ? plaintext.remaining() : 0)) {
            throw new RuntimeException("Invalid plaintext length");
        }

        boolean hasMetadata = metadata != null && metadata.remaining() > 0;
        boolean hasPlaintext = plaintext != null && plaintext.remaining() > 0;

        if (hasMetadata || !hasPlaintext) {
            this.xoofff.compress(hasMetadata ? metadata : XoodooStateHolder.EMPTY_BUFFER, (byte) (this.e ? 2 : 0), 2, metadataBitlen);
        }

        if (cryptogram == null) {
            cryptogram = new Cryptogram(plaintextBitlen);
        } else if (cryptogram.getBitlen() != plaintextBitlen || cryptogram.getCiphertext().remaining() != ((plaintextBitlen + 7) >>> 3)) {
            throw new RuntimeException("Ciphertext has invalid length");
        }

        if (hasPlaintext) {
            XoofffSavedState savedState = saveState();

            this.xoofff.compress(plaintext, (byte) (this.e ? 6 : 2), 3, plaintextBitlen);

            this.tag(cryptogram.getTag());
            swapState(savedState);
            this.xoofff.compress(cryptogram.getTag(), (byte) (this.e ? 7 : 3), 3, 256);
            this.xoofff.expand(plaintext, cryptogram.getCiphertext(), plaintextBitlen, 0);
            restoreStateNoCopy(savedState);
        } else {
            this.tag(cryptogram.getTag());
        }
        this.e = !this.e;

        return cryptogram;
    }

    private void tag(ByteBuffer tag) {
        if (tag.remaining() != 32) {
            throw new RuntimeException("XoofffSanse uses a tag-length of 32-bytes");
        }
        this.xoofff.expand(null, tag);
    }

    ByteBuffer unwrap(ByteBuffer metadata, Cryptogram cryptogram, long metadataBitlen, ByteBuffer plaintext) {
        if (((metadataBitlen + 7) >>> 3) != (metadata != null ? metadata.remaining() : 0)) {
            throw new RuntimeException("Invalid metadata length");
        }

        if (((cryptogram.getBitlen() + 7) >>> 3) != (cryptogram.getCiphertext() != null ? cryptogram.getCiphertext().remaining() : 0)) {
            throw new RuntimeException("Invalid ciphertext length");
        }

        if (cryptogram.getTag() == null || cryptogram.getTag().remaining() != 32) {
            throw new TagValidationException();
        }
        if (plaintext == null) {
            plaintext = ByteBuffer.allocate((int) ((cryptogram.getBitlen() + 7) >>> 3)).order(ByteOrder.LITTLE_ENDIAN);
        } else if (plaintext != null && plaintext.remaining() != ((cryptogram.getBitlen() + 7) >>> 3)) {
            throw new RuntimeException("Plaintext has invalid length");
        }

        boolean hasMetadata = metadata != null && metadataBitlen > 0;
        boolean hasCiphertext = cryptogram.getCiphertext() != null && cryptogram.getBitlen() > 0;

        if (hasMetadata || !hasCiphertext) {
            this.xoofff.compress(hasMetadata ? metadata : XoodooStateHolder.EMPTY_BUFFER, (byte) (this.e ? 2 : 0), 2, metadataBitlen);
        }

        if (hasCiphertext) {
            XoofffSavedState savedState = saveState();
            this.xoofff.compress(cryptogram.getTag(), (byte) (this.e ? 7 : 3), 3, 256);
            this.xoofff.expand(cryptogram.getCiphertext(), plaintext, cryptogram.getBitlen(), 0);
            restoreStateNoCopy(savedState);
            this.xoofff.compress(plaintext, (byte) (this.e ? 6 : 2), 3, cryptogram.getBitlen());
        }
        this.e = !this.e;

        StateSupplier state = this.xoofff.getExpandBuffer();
        int check = 0;
        ByteBuffer tag = cryptogram.getTag();
        ByteOrder tagOrder = tag.order();
        if (tagOrder != ByteOrder.LITTLE_ENDIAN) {
            tag.order(ByteOrder.LITTLE_ENDIAN);
        }

        check |= state.get(0) ^ tag.getInt(0);
        check |= state.get(1) ^ tag.getInt(4);
        check |= state.get(2) ^ tag.getInt(8);
        check |= state.get(3) ^ tag.getInt(12);
        check |= state.get(4) ^ tag.getInt(16);
        check |= state.get(5) ^ tag.getInt(20);
        check |= state.get(6) ^ tag.getInt(24);
        check |= state.get(7) ^ tag.getInt(28);

        if (check != 0) {
            throw new TagValidationException();
        }

        if (tagOrder != ByteOrder.LITTLE_ENDIAN) {
            tag.order(tagOrder);
        }

        return plaintext;
    }

    public ByteBuffer unwrap(byte[] metadata, Cryptogram cryptogram) {
        return unwrap(metadata != null ? ByteBuffer.wrap(metadata) : null,
                cryptogram,
            metadata != null ? ((long) metadata.length) << 3 : 0L, null);
    }
}
