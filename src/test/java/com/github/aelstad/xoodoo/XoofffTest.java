package com.github.aelstad.xoodoo;

import static org.junit.Assert.assertArrayEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.github.aelstad.keccakj.core.KeccakSponge;
import static com.github.aelstad.xoodoo.TestUtils.generateSimpleRawMaterial;

import org.junit.Test;

public class XoofffTest {
    final int XoodooSizeMultiplier = 16;
    final int SnP_widthInBytes = 3 * 4 * 4;
    final int SnP_width = SnP_widthInBytes * 8;
    final int inputByteSize = 2 * XoodooSizeMultiplier * SnP_widthInBytes + SnP_widthInBytes;
    final int outputByteSize = 2 * XoodooSizeMultiplier * SnP_widthInBytes + SnP_widthInBytes;
    final int keyByteSize = SnP_widthInBytes;
    final int inputBitSize = inputByteSize * 8;
    final int outputBitSize = outputByteSize * 8;
    final int keyBitSize = keyByteSize * 8;

    void performTestXoofffOneInput(int keyLen, int inputLen, int outputLen, KeccakSponge checksumSponge) 
    {   
        int seed = keyLen + outputLen + inputLen;
        seed ^= seed >>> 3;

        ByteBuffer input = generateSimpleRawMaterial((inputLen+7)>>>3, (seed + 0x13AD), (0x75 - seed));
        ByteBuffer key = generateSimpleRawMaterial((keyLen+7)>>>3, (seed + 0x2749), (0x31 - seed));
        ByteBuffer output = ByteBuffer.allocate((outputLen+7)>>>3).order(ByteOrder.LITTLE_ENDIAN);

        if ((inputLen & 7) != 0) {
            input.array()[inputLen >>> 3] &= (1 << (inputLen & 7)) - 1;
        }
        if ((keyLen & 7) != 0) {
            key.array()[keyLen >>> 3] &= (1 << (keyLen & 7)) - 1;
        }

        Xoofff xoofff = new Xoofff(key.array(), keyLen, false);

        xoofff.compress(input, (byte) 0, 0, (long) inputLen);
        xoofff.expand(null, output, (long) outputLen, 0);

        checksumSponge.getAbsorbStream().write(output.array());
    }

    @Test
    public void simpleTest() {
        byte[] key = new byte[1];
        byte[] input = new byte[1];
        ByteBuffer output = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);

        Xoofff xoofff = new Xoofff();
        xoofff.init(key, 8, false);
        xoofff.compress(ByteBuffer.wrap(input), (byte) 0, 0, 8L);

        xoofff.expand(null, output);

        assertThat(output.getInt(), is(0x6047ddfd));
        assertThat(output.getInt(), is(0xa94b7a62));
        assertThat(output.getInt(), is(0x939d6633));
        assertThat(output.getInt(), is(0x27bbcb83));
    }

    @Test
    public void complexTest() {
        int outputLen;
        int inputLen;
        int keyLen;

        KeccakSponge checksumSponge = new KeccakSponge(0, (byte) 0, 0);

        outputLen = 128*8;
        inputLen = 64*8;
        for(keyLen=0; keyLen<keyBitSize; keyLen = (keyLen < 2*SnP_width) ? (keyLen+1) : (keyLen+8)) {
            performTestXoofffOneInput(keyLen, inputLen, outputLen, checksumSponge);
        }

        outputLen = 128*8;
        keyLen = 16*8;
        for(inputLen=0; inputLen<=inputBitSize; inputLen = (inputLen < 2*SnP_width) ? (inputLen+1) : (inputLen+8)) {
            performTestXoofffOneInput(keyLen, inputLen, outputLen, checksumSponge);
        }

        inputLen = 64*8;
        keyLen = 16*8;
        for(outputLen=0; outputLen<=outputBitSize; outputLen = (outputLen < 2*SnP_width) ? (outputLen+1) : (outputLen+8)) {
            performTestXoofffOneInput(keyLen, inputLen, outputLen, checksumSponge);
        }

        checksumSponge.getAbsorbStream().close();
        byte[] checksum = new byte[16];

        checksumSponge.getSqueezeStream().read(checksum);

        assertArrayEquals(new byte[] {
            (byte) 0xca, (byte) 0x8e, (byte) 0x19, (byte) 0x14,
            (byte) 0xb6, (byte) 0xe2, (byte) 0x8f, (byte) 0xeb,
            (byte) 0x5f, (byte) 0xcb, (byte) 0xd2, (byte) 0x7d,
            (byte) 0xc2, (byte) 0x39, (byte) 0x2b, (byte) 0xd5
        }, checksum);

    }
}
