package com.github.aelstad.xoodoo;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public class XoodooTest {

    @Test
    public void canPermute4Rounds() {
        Xoodoo instance = new Xoodoo(4);
        instance.permute();

        int[] expected = new int[] { 0xbd5c1703,0x32c68715,0x4bb285d8,0x256a4278,0x271a4362,0x1d00135d,0x9c358bcb,0x8399ae4e,0xf8fb0e91,0xeaa3cc44,0x3c985ae6,0x82f5402e};
        assertArrayEquals(expected, instance.getState());
    }

    @Test
    public void canPermute6Rounds() {
        Xoodoo instance = new Xoodoo(6);
        instance.permute();

        int[] expected = new int[] { 0x28c9cea3,0xad204f60,0x2ec3d0d6,0xf050c7c5,0x08dc1225,0x61992304,0x9e0d402d,0x42d59b9b,0x1e6114fc,0x186eb697,0x35dbbc7f,0xa1f9104e };
        assertArrayEquals(expected, instance.getState());
    }

    @Test
    public void canPermute12Rounds() {
        Xoodoo instance = new Xoodoo(12);
        instance.permute();

        int[] expected = new int[] { 0x89d5d88d,0xa963fcbf,0x1b232d19,0xffa5a014,0x36b18106,0xafc7c1fe,0xaee57cbe,0xa77540bd,0x2e86e870,0xfef5b7c9,0x8b4fadf2,0x5e4f4062 };
        assertArrayEquals(expected, instance.getState());
    }

    @Test
    public void canPermute12Rounds384Times() {
        Xoodoo instance = new Xoodoo(12);
        for(int i=0; i < 384; ++i) {
            instance.permute();
        }

        int[] expected = new int[] { 0xfe04fab0,0x42d5d8ce,0x29c62ee7,0x2a7ae5cf,0xea36eba3,0x14649e0a,0xfe12521b,0xfe2eff69,0xf1826ca5,0xfc4c41e0,0x1597394f,0xeb092faf };
        assertArrayEquals(expected, instance.getState());
    }
}
