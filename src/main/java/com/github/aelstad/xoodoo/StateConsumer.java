package com.github.aelstad.xoodoo;

public interface StateConsumer {
    /**
     *
     * @param offset 0..11
     * @param value
     * @return
     */
    StateConsumer put(int offset, int value);
}
