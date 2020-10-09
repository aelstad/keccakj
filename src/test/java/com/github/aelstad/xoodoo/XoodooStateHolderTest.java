package com.github.aelstad.xoodoo;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class XoodooStateHolderTest {

    @Test
    public void canRollc() {

        int[] before = new int[] { 0x89d5d88d, 0xa963fcbf, 0x1b232d19, 0xffa5a014, 0x36b18106, 0xafc7c1fe, 0xaee57cbe, 0xa77540bd, 0x2e86e870, 0xfef5b7c9, 0x8b4fadf2, 0x5e4f4062 };

        int[] expected = new int[] { 0x36b18106, 0xafc7c1fe, 0xaee57cbe, 0xa77540bd, 0x2e86e870, 0xfef5b7c9, 0x8b4fadf2, 0x5e4f4062, 0xa963fcbf, 0x1b232d19, 0xffa5a014, 0x874870bc };

        XoodooStateHolder.rollc(before);

        assertArrayEquals(expected, before);
    }

    @Test
    public void canRolle() {

        int[] before = new int[] { 0x89d5d88d, 0xa963fcbf, 0x1b232d19, 0xffa5a014, 0x36b18106, 0xafc7c1fe, 0xaee57cbe, 0xa77540bd, 0x2e86e870, 0xfef5b7c9, 0x8b4fadf2, 0x5e4f4062 };

        int[] expected = new int[] { 0x36b18106, 0xafc7c1fe, 0xaee57cbe, 0xa77540bd, 0x2e86e870, 0xfef5b7c9, 0x8b4fadf2, 0x5e4f4062, 0xa963fcbf, 0x1b232d19, 0xffa5a014, 0x2c1b5760 };

        XoodooStateHolder.rolle(before);

        assertArrayEquals(expected, before);

    }
}