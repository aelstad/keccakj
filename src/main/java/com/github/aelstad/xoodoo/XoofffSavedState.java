package com.github.aelstad.xoodoo;

public final class XoofffSavedState {

    private int[] keyBuffer;
    private int[] compressedBuffer;

    private boolean flag;

    public XoofffSavedState(int[] keyBuffer, int[] compressedBuffer, boolean flag) {
        this.keyBuffer = keyBuffer;
        this.compressedBuffer = compressedBuffer;
        this.flag = flag;
    }

    public boolean isFlag() {
        return flag;
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }

    public XoofffSavedState(int[] keyBuffer, int[] compressedBuffer) {
        this.keyBuffer = keyBuffer;
        this.compressedBuffer = compressedBuffer;
	}

    public int[] getKeyBuffer() {
        return keyBuffer;
    }

    public void setKeyBuffer(int[] keyBuffer) {
        this.keyBuffer = keyBuffer;
    }

    public int[] getCompressedBuffer() {
        return compressedBuffer;
    }

    public void setCompressedBuffer(int[] compressedBuffer) {
        this.compressedBuffer = compressedBuffer;
    }
}
