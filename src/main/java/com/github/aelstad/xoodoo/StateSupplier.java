package com.github.aelstad.xoodoo;

public interface StateSupplier {
    /**
     *
     * @param offset 0..11
     * @param value
     * @return
     */
    int get(int offset);
}
