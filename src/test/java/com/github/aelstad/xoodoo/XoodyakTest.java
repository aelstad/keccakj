package com.github.aelstad.xoodoo;

import org.junit.Test;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertArrayEquals;
import static com.github.aelstad.xoodoo.TestUtils.generateSimpleRawMaterial;

public class XoodyakTest {

    @Test
    public void simpleHash() {
        Xoodyak instance = new Xoodyak(null, null, null);

        ByteBuffer data = generateSimpleRawMaterial(16, 253, 5);

        assertArrayEquals(new byte[] { (byte) 0x0d, (byte) 0xee, (byte) 0xcf, (byte) 0xb0, (byte) 0x91, (byte) 0x72,
                (byte) 0x53, (byte) 0x34, (byte) 0x14, (byte) 0xf5, (byte) 0xd6, (byte) 0xb7, (byte) 0x98, (byte) 0x79,
                (byte) 0x5a, (byte) 0x3b }, data.array());

        instance.absorb(data);
        byte[] out = new byte[16];
        instance.squeeze(ByteBuffer.wrap(out));

        assertArrayEquals(new byte[] { (byte) 0xf4, (byte) 0x24, (byte) 0xf0, (byte) 0x8c, (byte) 0xe5, (byte) 0xdf,
                (byte) 0x0c, (byte) 0x7f, (byte) 0xe9, (byte) 0x80, (byte) 0xf1, (byte) 0xce, (byte) 0x98, (byte) 0x54,
                (byte) 0x6d, (byte) 0x0e }, out);
    }

    @Test
    public void simpleKeyed() {

        ByteBuffer key = generateSimpleRawMaterial(19, 253, 5);

        assertArrayEquals(new byte[] { (byte) 0xf0, (byte) 0xd1, (byte) 0xb2, (byte) 0x93, (byte) 0x74, (byte) 0x55,
                (byte) 0x36, (byte) 0x17, (byte) 0xf7, (byte) 0xd8, (byte) 0xb9, (byte) 0x9a, (byte) 0x7b, (byte) 0x5c,
                (byte) 0x3d, (byte) 0x1e, (byte) 0xfe, (byte) 0xdf, (byte) 0xc0 }, key.array());

        Xoodyak instance = new Xoodyak(key.array(), key.array(), key.array());
        byte[] tag = new byte[19];
        instance.ratchet();
        instance.absorb(key);
        instance.ratchet();
        instance.squeeze(ByteBuffer.wrap(tag));

        assertArrayEquals(new byte[] { (byte) 0xef, (byte) 0xb5, (byte) 0x62, (byte) 0x09, (byte) 0x51, (byte) 0x63,
                (byte) 0x5d, (byte) 0x7a, (byte) 0x22, (byte) 0x1b, (byte) 0x91, (byte) 0xeb, (byte) 0x9b, (byte) 0xbe,
                (byte) 0xe3, (byte) 0x67, (byte) 0x65, (byte) 0xd4, (byte) 0x8f }, tag);

        byte[] ciphertext = new byte[19];

        instance.encrypt(key, ByteBuffer.wrap(ciphertext));

        assertArrayEquals(new byte[] { (byte) 0x72, (byte) 0xd3, (byte) 0xfd, (byte) 0xfe, (byte) 0x9a, (byte) 0x82,
                (byte) 0xae, (byte) 0x93, (byte) 0x99, (byte) 0xce, (byte) 0x19, (byte) 0x4b, (byte) 0x77, (byte) 0x26,
                (byte) 0xa6, (byte) 0xd0, (byte) 0x5e, (byte) 0x4a, (byte) 0x8b }, ciphertext);

        byte[] squeezedKey = new byte[19];
        instance.squeezeKey(ByteBuffer.wrap(squeezedKey));

        assertArrayEquals(new byte[] { (byte) 0x3a, (byte) 0x68, (byte) 0xc2, (byte) 0xb6, (byte) 0x36, (byte) 0x08,
                (byte) 0xad, (byte) 0x73, (byte) 0x7a, (byte) 0x4b, (byte) 0x56, (byte) 0x78, (byte) 0x47, (byte) 0x49,
                (byte) 0x50, (byte) 0xa7, (byte) 0x64, (byte) 0x81, (byte) 0xf9 }, squeezedKey);

        instance = new Xoodyak(key.array(), key.array(), key.array());
        instance.ratchet();
        instance.absorb(key);
        instance.ratchet();
        byte[] tag2 = new byte[19];
        instance.squeeze(ByteBuffer.wrap(tag2));

        assertArrayEquals(tag, tag2);

        byte[] plaintext = new byte[19];
        instance.decrypt(ByteBuffer.wrap(ciphertext), ByteBuffer.wrap(plaintext));

        assertArrayEquals(key.array(), plaintext);

        byte[] squeezedKey2 = new byte[19];
        instance.squeezeKey(ByteBuffer.wrap(squeezedKey2));

        assertArrayEquals(squeezedKey, squeezedKey2);
    }

    @Test
    public void complexHash() {
        final int MAX_NUMBER_MESSAGES = 3;
        final int MAX_MESSAGE_LEN = 3 * 48 + 1;
        final int MAX_HASH_LEN = 3 * 48 + 1;
        final int TYPICAL_HASH_LEN = 32;

        Xoodyak global = new Xoodyak(null, null, null);

        for (int i = 1; i < MAX_NUMBER_MESSAGES; ++i) {
            for (int l = 0; l < MAX_MESSAGE_LEN; ++l) {
                testXoodyakHashOne(global, l, TYPICAL_HASH_LEN, i);
            }
        }

        for (int i = 1; i < MAX_HASH_LEN; ++i) {
            testXoodyakHashOne(global, MAX_MESSAGE_LEN, i, 1);
        }

        byte[] out = global.squeezeNew(32);
        assertArrayEquals(new byte[] { (byte) 0x72, (byte) 0xbb, (byte) 0x07, (byte) 0xae, (byte) 0x9c, (byte) 0xae,
                (byte) 0x32, (byte) 0xb3, (byte) 0x0e, (byte) 0xa4, (byte) 0x73, (byte) 0x65, (byte) 0x67, (byte) 0x01,
                (byte) 0xf3, (byte) 0xd8, (byte) 0x25, (byte) 0xbd, (byte) 0x56, (byte) 0x82, (byte) 0x1b, (byte) 0xb6,
                (byte) 0xa4, (byte) 0x5d, (byte) 0x2c, (byte) 0xba, (byte) 0xbc, (byte) 0x50, (byte) 0x78, (byte) 0xab,
                (byte) 0x4c, (byte) 0x7a }, out);
    }

    @Test
    public void keyedComplex() {
        final int Xoodyak_MaxKeySize = 48 - 4 - 1;
        final int Xoodyak_MaxNonceSize = 16;
        final int Xoodyak_DataSize = 3 * 48 + 1;

        Xoodyak global = new Xoodyak(null, null, null);

        for (int keyVariant = 0; keyVariant < 2; ++keyVariant) {
            for (int ratchet = 0; ratchet < 3; ++ratchet) {
                for (int newKlen = 0; newKlen <= Xoodyak_MaxKeySize; newKlen += 16) {
                    for (int Klen = 16; Klen <= Xoodyak_MaxKeySize; ++Klen) {
                        for (int Nlen = 0; Nlen <= Xoodyak_MaxNonceSize; Nlen += (Klen == 16) ? 1
                                : Xoodyak_MaxNonceSize) {
                            ByteBuffer KAndID = generateSimpleRawMaterial(Klen, (Klen + Nlen + 0x12) & 0xff, 3);
                            ByteBuffer N = generateSimpleRawMaterial(Nlen, (Klen + Nlen + 0x45) & 0xff, 6);

                            final int c = 0x1234 + keyVariant + 3 * ratchet + 5 * newKlen + 9 * Nlen;
                            final int IDlen = ((Klen <= 16) || (keyVariant == 2)) ? 0 : (c % (Klen - (16 - 1)));

                            byte[] K = new byte[Klen - IDlen];
                            KAndID.get(K, 0, K.length);
                            byte[] ID = new byte[IDlen];
                            KAndID.get(ID, 0, IDlen);

                            ByteBuffer AD = ByteBuffer.wrap(new byte[] { (byte) 'A', (byte) 'B', (byte) 'C' });
                            ByteBuffer P = ByteBuffer.wrap(new byte[] { (byte) 'D', (byte) 'E', (byte) 'F' });

                            testXoodyakKeyedOne(global, K, ID, N.array(), AD, P, 1, keyVariant, ratchet, newKlen);

                        }
                    }
                }
            }
        }

        {
            final int[] Alengths = new int[] { 0, 1, 48 - 4 - 1, 48 - 4, 48 - 4 + 1 };

            final int newKlen = 0;
            final int Klen = 16;
            final int Nlen = 16;
            final int keyVariant = 0;
            for (int ratchet = 0; ratchet < 3; ++ratchet) {
                for (int nbrMessagesInSession = 1; nbrMessagesInSession <= 3; ++nbrMessagesInSession) {
                    for (int Aleni = 0; Aleni < 5; Aleni++) {
                        for (int Mlen = 0; Mlen <= Xoodyak_DataSize; Mlen += (Aleni == 0) ? 1 : (ratchet * 4 + 1)) {
                            final int Alen = Alengths[Aleni];

                            ByteBuffer K = generateSimpleRawMaterial(Klen, (0x23 + Mlen + Alen) & 0xff, 4);
                            ByteBuffer N = generateSimpleRawMaterial(Nlen, (0x56 + Mlen + Alen) & 0xff, 7);
                            ByteBuffer A = generateSimpleRawMaterial(Alen, (0xAB + Mlen + Alen) & 0xff, 3);
                            ByteBuffer P = generateSimpleRawMaterial(Mlen, (0xCD + Mlen + Alen) & 0xff, 4);

                            testXoodyakKeyedOne(global, K.array(), null, N.array(), P, A, nbrMessagesInSession,
                                    keyVariant, ratchet, newKlen);
                        }
                    }
                }
            }
        }
        {
            final int Mlengths[] = new int[] { 0, 1, 24 - 1, 24, 24 + 1 };

            final int newKlen = 0;
            final int Klen = 16;
            final int Nlen = 16;
            final int keyVariant = 0;
            for (int ratchet = 0; ratchet < 3; ++ratchet) {
                for (int nbrMessagesInSession = 1; nbrMessagesInSession <= 3; ++nbrMessagesInSession) {
                    for (int Mleni = 0; Mleni < 5; Mleni++) {
                        for (int Alen = 0; Alen <= Xoodyak_DataSize; Alen += (Mleni == 0) ? 1 : (ratchet * 4 + 1)) {

                            final int Mlen = Mlengths[Mleni];

                            ByteBuffer K = generateSimpleRawMaterial(Klen, (0x34 + Mlen + Alen) & 0xff, 5);
                            ByteBuffer N = generateSimpleRawMaterial(Nlen, (0x45 + Mlen + Alen) & 0xff, 6);
                            ByteBuffer A = generateSimpleRawMaterial(Alen, (0x01 + Mlen + Alen) & 0xff, 5);
                            ByteBuffer P = generateSimpleRawMaterial(Mlen, (0x23 + Mlen + Alen) & 0xff, 6);

                            testXoodyakKeyedOne(global, K.array(), null, N.array(), P, A, nbrMessagesInSession,
                                    keyVariant, ratchet, newKlen);
                        }
                    }
                }
            }
        }
        byte[] out = global.squeezeNew(32);
        assertArrayEquals(new byte[] { (byte) 0xaa, (byte) 0x2c, (byte) 0x40, (byte) 0x75, (byte) 0x31, (byte) 0x3f,
                (byte) 0xce, (byte) 0x6a, (byte) 0x55, (byte) 0xed, (byte) 0xa0, (byte) 0x40, (byte) 0xf9, (byte) 0xd0,
                (byte) 0x02, (byte) 0x54, (byte) 0x0e, (byte) 0x4b, (byte) 0xd1, (byte) 0x2e, (byte) 0xa0, (byte) 0x8d,
                (byte) 0x52, (byte) 0x3d, (byte) 0x48, (byte) 0x86, (byte) 0x34, (byte) 0xe2, (byte) 0x97, (byte) 0x89,
                (byte) 0xd6, (byte) 0xd8 }, out);
    }

    void testXoodyakHashOne(Xoodyak global, int messageLen, int hashLen, int numberOfMessages) {
        Xoodyak instance = new Xoodyak(null, null, null);
        for (int i = 0; i < numberOfMessages; ++i) {
            ByteBuffer buffer = generateSimpleRawMaterial(messageLen, (messageLen + hashLen + 0x12), 3);

            instance.absorb(buffer);
        }
        ByteBuffer out = ByteBuffer.allocate(hashLen);

        instance.squeeze(out);

        global.absorb(out);
    }

    void testXoodyakKeyedOne(Xoodyak global, byte[] key, byte[] id, byte[] nonce, ByteBuffer AD, ByteBuffer P,
            int nbrMessagesInSession, int keyVariant, int ratchet, int squeezeKLen) {
        Xoodyak encrypt = null;
        Xoodyak decrypt = null;

        if (keyVariant == 0) {
            encrypt = new Xoodyak(key, id, null);
            encrypt.absorb(ByteBuffer.wrap(nonce));
            decrypt = new Xoodyak(key, id, null);
            decrypt.absorb(ByteBuffer.wrap(nonce));
        } else if (keyVariant == 1) {
            encrypt = new Xoodyak(key, id, nonce);
            decrypt = new Xoodyak(key, id, nonce);
        }
        for ( /* empty */; nbrMessagesInSession != 0; --nbrMessagesInSession) {
            if (squeezeKLen != 0) {
                ByteBuffer squezeKeyEncrypt = ByteBuffer.allocate(squeezeKLen);
                ByteBuffer squezeKeyDecrypt = ByteBuffer.allocate(squeezeKLen);

                encrypt.squeezeKey(squezeKeyEncrypt);
                decrypt.squeezeKey(squezeKeyDecrypt);

                assertArrayEquals(squezeKeyEncrypt.array(), squezeKeyDecrypt.array());

                global.absorb(squezeKeyEncrypt);
            }
            encrypt.absorb(AD);
            decrypt.absorb(AD);

            ByteBuffer C = ByteBuffer.allocate(P.limit());
            ByteBuffer PDecrypted = ByteBuffer.allocate(P.limit());

            encrypt.encrypt(P, C);
            decrypt.decrypt(C, PDecrypted);

            assertArrayEquals(P.array(), PDecrypted.array());

            global.absorb(C);

            if (ratchet == 1) {
                encrypt.ratchet();
                decrypt.ratchet();
            }

            byte[] TEncrypt = encrypt.squeezeNew(16);
            byte[] TDecrypt = decrypt.squeezeNew(16);
            assertArrayEquals(TEncrypt, TDecrypt);

            global.absorb(ByteBuffer.wrap(TEncrypt));

            if (ratchet == 2) {
                encrypt.ratchet();
                decrypt.ratchet();
            }
        }
    }

}
