package com.github.aelstad.xoodoo;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.github.aelstad.keccakj.core.KeccakSponge;

import org.junit.Test;

import static com.github.aelstad.xoodoo.TestUtils.generateSimpleRawMaterial;

public class XoofffSanseTest {
    final int XoodooSizeMultiplier=16;
    final int SnP_widthInBytes=3*4*4;
    final int SnP_width=SnP_widthInBytes*8;
    final int dataByteSize=2*XoodooSizeMultiplier*SnP_widthInBytes+SnP_widthInBytes;
    final int ADByteSize=2*XoodooSizeMultiplier*SnP_widthInBytes+SnP_widthInBytes;
    final int keyByteSize=SnP_widthInBytes;
    
    final int dataBitSize=dataByteSize*8;
    final int keyBitSize=keyByteSize*8;
    final int ADBitSize=ADByteSize*8;

    @Test
    public void simple() {
        byte[] key = new byte[0];
        
        byte[] plaintext = new byte[1];
        plaintext[0] = (byte) 0x51;
        byte[] metadata = new byte[1];
        metadata[0] = (byte) 0x3a;

        XoofffSanse encryptor = new XoofffSanse(key, 0);
        XoofffSanse decryptor = new XoofffSanse(key, 0);

        Cryptogram cryptogram = encryptor.wrap(metadata, plaintext);

        assertArrayEquals(
            new byte[] {
                (byte) 0x95, (byte) 0xed, (byte) 0xd6, (byte) 0xa6,
                (byte) 0xc9, (byte) 0xdd, (byte) 0xa8, (byte) 0x3a,
                (byte) 0xb8, (byte) 0xa3, (byte) 0x45, (byte) 0xd5,
                (byte) 0x01, (byte) 0x5e, (byte) 0xeb, (byte) 0x3a,
                (byte) 0x42, (byte) 0xf8, (byte) 0xa9, (byte) 0xa5,
                (byte) 0x50, (byte) 0x1e, (byte) 0x0a, (byte) 0xd8,
                (byte) 0x9a, (byte) 0x17, (byte) 0xba, (byte) 0x76,
                (byte) 0x2c, (byte) 0xbf, (byte) 0xe4, (byte) 0x58},
            cryptogram.getTag().array());

        assertArrayEquals(new byte[] { 0x09}, cryptogram.getCiphertext().array());

        byte[] decryptedPlaintext = decryptor.unwrap(metadata, cryptogram).array();
        assertArrayEquals(plaintext, decryptedPlaintext);

        Cryptogram cryptogram2 = encryptor.wrap(metadata, plaintext);
        assertArrayEquals(
            new byte[] {
                (byte) 0x79, (byte) 0x0e, (byte) 0xd2, (byte) 0x0d,
                (byte) 0xb8, (byte) 0x71, (byte) 0x96, (byte) 0xad,
                (byte) 0xc0, (byte) 0xc8, (byte) 0x69, (byte) 0xea,
                (byte) 0xe8, (byte) 0x8b, (byte) 0xfc, (byte) 0xa2,
                (byte) 0x93, (byte) 0x4b, (byte) 0xe1, (byte) 0x33,
                (byte) 0x5a, (byte) 0x9d, (byte) 0x29, (byte) 0x7f,
                (byte) 0xfe, (byte) 0xe4, (byte) 0xb2, (byte) 0x7f,
                (byte) 0xc1, (byte) 0xd7, (byte) 0xb8, (byte) 0x78
            },
            cryptogram2.getTag().array());

        assertArrayEquals(new byte[] {0x5f}, cryptogram2.getCiphertext().array());

        assertFalse(Arrays.equals(cryptogram.getTag().array(), cryptogram2.getTag().array()));
        assertFalse(Arrays.equals(cryptogram.getCiphertext().array(), cryptogram2.getCiphertext().array()));

        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        decryptor.init(key, 0);
        metadata[0] ^= 1;
        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        metadata[0] ^= 1;

        decryptor.init(key, 0);
        cryptogram.getCiphertext().put(0, (byte) (cryptogram.getCiphertext().get(0) ^ 1));
        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        cryptogram.getCiphertext().put(0, (byte) (cryptogram.getCiphertext().get(0) ^ 1));

        decryptor.init(key, 0);
        cryptogram.getTag().put(0, (byte) (cryptogram.getTag().get(0) ^ 1));
        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        cryptogram.getTag().put(0, (byte) (cryptogram.getTag().get(0) ^ 1));

        decryptor.init(key, 0);
        cryptogram.getTag().put(31, (byte) (cryptogram.getTag().get(31) ^ 1));
        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        cryptogram.getTag().put(31, (byte) (cryptogram.getTag().get(31) ^ 1));

        decryptor.init(key, 0);
        cryptogram.getTag().limit(31);
        assertThrows(TagValidationException.class, () -> decryptor.unwrap(metadata, cryptogram));
        cryptogram.getTag().limit(32);

        decryptor.init(key, 0);
        assertNotNull(decryptor.unwrap(metadata, cryptogram));
    }

    void performTestXoofffSanseOneInput(int keyLen, int dataLen, int ADLen, KeccakSponge checksumSponge)
    {
        int seed = keyLen + dataLen + ADLen;
        seed ^= seed >>> 3;

        ByteBuffer key = generateSimpleRawMaterial((keyLen+7)>>>3, (0x4321 - seed), (0x89 + seed));

        ByteBuffer input = generateSimpleRawMaterial((dataLen+7)>>>3, (0x6523 - seed), (0x43 + seed));

        ByteBuffer AD = generateSimpleRawMaterial((ADLen + 7) / 8, (0x1A29 - seed), 0xC3 + seed);

        if ((keyLen & 7) != 0) {
            key.array()[keyLen >>> 3] &= (1 << (keyLen & 7)) - 1;
        }
        if ((dataLen & 7) != 0) {
            input.array()[dataLen >>> 3] &= (1 << (dataLen & 7)) - 1;
        }
        if ((ADLen & 7) != 0) {
            AD.array()[ADLen >>> 3] &= (1 << (ADLen & 7)) - 1;
        }

        XoofffSanse encryptor = new XoofffSanse();
        XoofffSanse decryptor = new XoofffSanse();

        encryptor.init(key.array(), keyLen);
        decryptor.init(key.array(), keyLen);

        for (int session = 3; session != 0; --session) {
            Cryptogram cryptogram = encryptor.wrap(AD, input, ADLen, dataLen, null);
            ByteBuffer decrypted = decryptor.unwrap(AD, cryptogram, ADLen, null);
            if (dataLen > 0) {
                assertArrayEquals(input.array(), decrypted.array());
                checksumSponge.getAbsorbStream().write(cryptogram.getCiphertext().array());
            }
            checksumSponge.getAbsorbStream().write(cryptogram.getTag().array());
        }
    }

    @Test
    public void complex() {
        int dataLen;
        int ADLen;
        int keyLen;

        KeccakSponge checksumSponge = new KeccakSponge(0, (byte) 0, 0);

        dataLen = 128*8;
        ADLen = 64*8;    
        for(keyLen=0; keyLen<keyBitSize; keyLen = (keyLen < 2*SnP_width) ? (keyLen+1) : (keyLen+8)) {
            performTestXoofffSanseOneInput(keyLen, dataLen, ADLen, checksumSponge);
        }

        ADLen = 64*8;
        keyLen = 16*8;
        for(dataLen=0; dataLen<=dataBitSize; dataLen = (dataLen < 2*SnP_width) ? (dataLen+1) : (dataLen+8)) {
            performTestXoofffSanseOneInput(keyLen, dataLen, ADLen, checksumSponge);
        }

        dataLen = 128*8;
        keyLen = 16*8;
        for(ADLen=0; ADLen<=ADBitSize; ADLen = (ADLen < 2*SnP_width) ? (ADLen+1) : (ADLen+8)) {
            performTestXoofffSanseOneInput(keyLen, dataLen, ADLen, checksumSponge);
        }

        checksumSponge.getAbsorbStream().close();
        byte[] checksum = new byte[16];

        checksumSponge.getSqueezeStream().read(checksum);

        assertArrayEquals(new byte[] {
            (byte) 0x06, (byte) 0xed, (byte) 0xf9, (byte) 0xa6,
            (byte) 0x70, (byte) 0xb3, (byte) 0xfe, (byte) 0x83,
            (byte) 0x34, (byte) 0x2c, (byte) 0xb4, (byte) 0x18,
            (byte) 0x75, (byte) 0x0d, (byte) 0xf2, (byte) 0xcc
        }, checksum);
    }
}
