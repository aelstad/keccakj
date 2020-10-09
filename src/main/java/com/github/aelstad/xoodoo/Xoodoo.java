package com.github.aelstad.xoodoo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class Xoodoo {

    private final static int RC[] = {
        0x00000012,
        0x000001A0,
        0x000000F0,
        0x00000380,
        0x0000002C,
        0x00000060,
        0x00000014,
        0x00000120,
        0x000000D0,
        0x000003C0,
        0x00000038,
        0x00000058
    };

    private int rounds;
    private XoodooStateHolder state;

    public Xoodoo(int rounds) {
        this.rounds = rounds;
        this.state = XoodooStateHolder.create();
    }

    public int[] getState() {
        return this.state.getState();
    }

    /**
     * @param inState 48-byte ByteBuffer in little-endian format (as returned by getStateBuffer())
     * @param outState 12-items 32-bit int-array (native order)
     */
    public static void permuteAndAdd(StateSupplier inState, int[] outState, int rounds) {
        int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;

        s0 = inState.get(0);
        s1 = inState.get(1);
        s2 = inState.get(2);
        s3 = inState.get(3);
        s4 = inState.get(4);
        s5 = inState.get(5);
        s6 = inState.get(6);
        s7 = inState.get(7);
        s8 = inState.get(8);
        s9 = inState.get(9);
        s10 = inState.get(10);
        s11 = inState.get(11);

        for (int i = rounds - 1; i >= 0; --i) {

            // θ step, ρ West step and ι step
            final int p0 = s0 ^ s4 ^ s8;
            final int p1 = s1 ^ s5 ^ s9;
            final int p2 = s2 ^ s6 ^ s10;
            final int p3 = s3 ^ s7 ^ s11;

            final int e0 = (((p3 << 5) | (p3 >>> 27))) ^  (((p3 << 14) | (p3 >>> 18)));
            final int e1 = (((p0 << 5) | (p0 >>> 27))) ^  (((p0 << 14) | (p0 >>> 18)));
            final int e2 = (((p1 << 5) | (p1 >>> 27))) ^  (((p1 << 14) | (p1 >>> 18)));
            final int e3 = (((p2 << 5) | (p2 >>> 27))) ^  (((p2 << 14) | (p2 >>> 18)));

            final int pl0 = s0 ^ e0 ^ Xoodoo.RC[i];
            final int pl1 = s1 ^ e1;
            final int pl2 = s2 ^ e2;
            final int pl3 = s3 ^ e3;
            final int pl4 = s7 ^ e3;
            final int pl5 = s4 ^ e0;
            final int pl6 = s5 ^ e1;
            final int pl7 = s6 ^ e2;

            final int pw8 = s8 ^ e0;
            final int pw9 = s9 ^ e1;
            final int pw10 = s10 ^ e2;
            final int pw11 = s11 ^ e3;

            final int pl8 = (pw8 << 11) | (pw8 >>> 21);
            final int pl9 = (pw9 << 11) | (pw9 >>> 21);
            final int pl10 = (pw10 << 11) | (pw10 >>> 21);
            final int pl11 = (pw11 << 11) | (pw11 >>> 21);

            // χ step
            final int b0 = (~pl4) & pl8;
            final int b1 = (~pl5) & pl9;
            final int b2 = (~pl6) & pl10;
            final int b3 = (~pl7) & pl11;
            final int b4 = (~pl8) & pl0;
            final int b5 = (~pl9) & pl1;
            final int b6 = (~pl10) & pl2;
            final int b7 = (~pl11) & pl3;
            final int b8 = (~pl0) & pl4;
            final int b9 = (~pl1) & pl5;
            final int b10 = (~pl2) & pl6;
            final int b11 = (~pl3) & pl7;

            s0 = pl0 ^ b0;
            s1 = pl1 ^ b1;
            s2 = pl2 ^ b2;
            s3 = pl3 ^ b3;

            // ρ East step
            final int pe4 = pl4 ^ b4;
            final int pe5 = pl5 ^ b5;
            final int pe6 = pl6 ^ b6;
            final int pe7 = pl7 ^ b7;
            final int pe8 = pl10 ^ b10;
            final int pe9 = pl11 ^ b11;
            final int pe10 = pl8 ^ b8;
            final int pe11 = pl9 ^ b9;

            s4 = (pe4 << 1) | (pe4 >>> 31);
            s5 = (pe5 << 1) | (pe5 >>> 31);
            s6 = (pe6 << 1) | (pe6 >>> 31);
            s7 = (pe7 << 1) | (pe7 >>> 31);
            s8 = (pe8 << 8) | (pe8 >>> 24);
            s9 = (pe9 << 8) | (pe9 >>> 24);
            s10 = (pe10 << 8) | (pe10 >>> 24);;
            s11 = (pe11 << 8) | (pe11 >>> 24);;
        }
        outState[0] ^= s0;
        outState[1] ^= s1;
        outState[2] ^= s2;
        outState[3] ^= s3;
        outState[4] ^= s4;
        outState[5] ^= s5;
        outState[6] ^= s6;
        outState[7] ^= s7;
        outState[8] ^= s8;
        outState[9] ^= s9;
        outState[10] ^= s10;
        outState[11] ^= s11;
    }


    public static void permuteAndSet(StateSupplier inState, int[] outState, int rounds) {
        int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;

        s0 = inState.get(0);
        s1 = inState.get(1);
        s2 = inState.get(2);
        s3 = inState.get(3);
        s4 = inState.get(4);
        s5 = inState.get(5);
        s6 = inState.get(6);
        s7 = inState.get(7);
        s8 = inState.get(8);
        s9 = inState.get(9);
        s10 = inState.get(10);
        s11 = inState.get(11);

        for (int i = rounds - 1; i >= 0; --i) {

            // θ step, ρ West step and ι step
            final int p0 = s0 ^ s4 ^ s8;
            final int p1 = s1 ^ s5 ^ s9;
            final int p2 = s2 ^ s6 ^ s10;
            final int p3 = s3 ^ s7 ^ s11;

            final int e0 = (((p3 << 5) | (p3 >>> 27))) ^  (((p3 << 14) | (p3 >>> 18)));
            final int e1 = (((p0 << 5) | (p0 >>> 27))) ^  (((p0 << 14) | (p0 >>> 18)));
            final int e2 = (((p1 << 5) | (p1 >>> 27))) ^  (((p1 << 14) | (p1 >>> 18)));
            final int e3 = (((p2 << 5) | (p2 >>> 27))) ^  (((p2 << 14) | (p2 >>> 18)));

            final int pl0 = s0 ^ e0 ^ Xoodoo.RC[i];
            final int pl1 = s1 ^ e1;
            final int pl2 = s2 ^ e2;
            final int pl3 = s3 ^ e3;
            final int pl4 = s7 ^ e3;
            final int pl5 = s4 ^ e0;
            final int pl6 = s5 ^ e1;
            final int pl7 = s6 ^ e2;

            final int pw8 = s8 ^ e0;
            final int pw9 = s9 ^ e1;
            final int pw10 = s10 ^ e2;
            final int pw11 = s11 ^ e3;

            final int pl8 = (pw8 << 11) | (pw8 >>> 21);
            final int pl9 = (pw9 << 11) | (pw9 >>> 21);
            final int pl10 = (pw10 << 11) | (pw10 >>> 21);
            final int pl11 = (pw11 << 11) | (pw11 >>> 21);

            // χ step
            final int b0 = (~pl4) & pl8;
            final int b1 = (~pl5) & pl9;
            final int b2 = (~pl6) & pl10;
            final int b3 = (~pl7) & pl11;
            final int b4 = (~pl8) & pl0;
            final int b5 = (~pl9) & pl1;
            final int b6 = (~pl10) & pl2;
            final int b7 = (~pl11) & pl3;
            final int b8 = (~pl0) & pl4;
            final int b9 = (~pl1) & pl5;
            final int b10 = (~pl2) & pl6;
            final int b11 = (~pl3) & pl7;

            s0 = pl0 ^ b0;
            s1 = pl1 ^ b1;
            s2 = pl2 ^ b2;
            s3 = pl3 ^ b3;

            // ρ East step
            final int pe4 = pl4 ^ b4;
            final int pe5 = pl5 ^ b5;
            final int pe6 = pl6 ^ b6;
            final int pe7 = pl7 ^ b7;
            final int pe8 = pl10 ^ b10;
            final int pe9 = pl11 ^ b11;
            final int pe10 = pl8 ^ b8;
            final int pe11 = pl9 ^ b9;

            s4 = (pe4 << 1) | (pe4 >>> 31);
            s5 = (pe5 << 1) | (pe5 >>> 31);
            s6 = (pe6 << 1) | (pe6 >>> 31);
            s7 = (pe7 << 1) | (pe7 >>> 31);
            s8 = (pe8 << 8) | (pe8 >>> 24);
            s9 = (pe9 << 8) | (pe9 >>> 24);
            s10 = (pe10 << 8) | (pe10 >>> 24);;
            s11 = (pe11 << 8) | (pe11 >>> 24);;
        }
        outState[0] = s0;
        outState[1] = s1;
        outState[2] = s2;
        outState[3] = s3;
        outState[4] = s4;
        outState[5] = s5;
        outState[6] = s6;
        outState[7] = s7;
        outState[8] = s8;
        outState[9] = s9;
        outState[10] = s10;
        outState[11] = s11;
    }


    /**
     * @param inState  12-item 32-bit-int array (native order)
     * @param outState 12-item 32-bit-int array (native order)
     */
    public static void permuteAndSet(int[] inState,  int[] outState, int rounds) {
        int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;

        s0 = inState[0];
        s1 = inState[1];
        s2 = inState[2];
        s3 = inState[3];
        s4 = inState[4];
        s5 = inState[5];
        s6 = inState[6];
        s7 = inState[7];
        s8 = inState[8];
        s9 = inState[9];
        s10 = inState[10];
        s11 = inState[11];

        for (int i = rounds - 1; i >= 0; --i) {

            // θ step, ρ West step and ι step
            final int p0 = s0 ^ s4 ^ s8;
            final int p1 = s1 ^ s5 ^ s9;
            final int p2 = s2 ^ s6 ^ s10;
            final int p3 = s3 ^ s7 ^ s11;

            final int e0 = (((p3 << 5) | (p3 >>> 27))) ^  (((p3 << 14) | (p3 >>> 18)));
            final int e1 = (((p0 << 5) | (p0 >>> 27))) ^  (((p0 << 14) | (p0 >>> 18)));
            final int e2 = (((p1 << 5) | (p1 >>> 27))) ^  (((p1 << 14) | (p1 >>> 18)));
            final int e3 = (((p2 << 5) | (p2 >>> 27))) ^  (((p2 << 14) | (p2 >>> 18)));

            final int pl0 = s0 ^ e0 ^ Xoodoo.RC[i];
            final int pl1 = s1 ^ e1;
            final int pl2 = s2 ^ e2;
            final int pl3 = s3 ^ e3;
            final int pl4 = s7 ^ e3;
            final int pl5 = s4 ^ e0;
            final int pl6 = s5 ^ e1;
            final int pl7 = s6 ^ e2;

            final int pw8 = s8 ^ e0;
            final int pw9 = s9 ^ e1;
            final int pw10 = s10 ^ e2;
            final int pw11 = s11 ^ e3;

            final int pl8 = (pw8 << 11) | (pw8 >>> 21);
            final int pl9 = (pw9 << 11) | (pw9 >>> 21);
            final int pl10 = (pw10 << 11) | (pw10 >>> 21);
            final int pl11 = (pw11 << 11) | (pw11 >>> 21);

            // χ step
            final int b0 = (~pl4) & pl8;
            final int b1 = (~pl5) & pl9;
            final int b2 = (~pl6) & pl10;
            final int b3 = (~pl7) & pl11;
            final int b4 = (~pl8) & pl0;
            final int b5 = (~pl9) & pl1;
            final int b6 = (~pl10) & pl2;
            final int b7 = (~pl11) & pl3;
            final int b8 = (~pl0) & pl4;
            final int b9 = (~pl1) & pl5;
            final int b10 = (~pl2) & pl6;
            final int b11 = (~pl3) & pl7;

            s0 = pl0 ^ b0;
            s1 = pl1 ^ b1;
            s2 = pl2 ^ b2;
            s3 = pl3 ^ b3;

            // ρ East step
            final int pe4 = pl4 ^ b4;
            final int pe5 = pl5 ^ b5;
            final int pe6 = pl6 ^ b6;
            final int pe7 = pl7 ^ b7;
            final int pe8 = pl10 ^ b10;
            final int pe9 = pl11 ^ b11;
            final int pe10 = pl8 ^ b8;
            final int pe11 = pl9 ^ b9;

            s4 = (pe4 << 1) | (pe4 >>> 31);
            s5 = (pe5 << 1) | (pe5 >>> 31);
            s6 = (pe6 << 1) | (pe6 >>> 31);
            s7 = (pe7 << 1) | (pe7 >>> 31);
            s8 = (pe8 << 8) | (pe8 >>> 24);
            s9 = (pe9 << 8) | (pe9 >>> 24);
            s10 = (pe10 << 8) | (pe10 >>> 24);;
            s11 = (pe11 << 8) | (pe11 >>> 24);;
        }
        outState[0] = s0;
        outState[1] = s1;
        outState[2] = s2;
        outState[3] = s3;
        outState[4] = s4;
        outState[5] = s5;
        outState[6] = s6;
        outState[7] = s7;
        outState[8] = s8;
        outState[9] = s9;
        outState[10]= s10;
        outState[11] = s11;
    }

    public static void permuteAndConsume(int[] inState,  StateConsumer outState, int rounds) {
        int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;

        s0 = inState[0];
        s1 = inState[1];
        s2 = inState[2];
        s3 = inState[3];
        s4 = inState[4];
        s5 = inState[5];
        s6 = inState[6];
        s7 = inState[7];
        s8 = inState[8];
        s9 = inState[9];
        s10 = inState[10];
        s11 = inState[11];

        for (int i = rounds - 1; i >= 0; --i) {

            // θ step, ρ West step and ι step
            final int p0 = s0 ^ s4 ^ s8;
            final int p1 = s1 ^ s5 ^ s9;
            final int p2 = s2 ^ s6 ^ s10;
            final int p3 = s3 ^ s7 ^ s11;

            final int e0 = (((p3 << 5) | (p3 >>> 27))) ^  (((p3 << 14) | (p3 >>> 18)));
            final int e1 = (((p0 << 5) | (p0 >>> 27))) ^  (((p0 << 14) | (p0 >>> 18)));
            final int e2 = (((p1 << 5) | (p1 >>> 27))) ^  (((p1 << 14) | (p1 >>> 18)));
            final int e3 = (((p2 << 5) | (p2 >>> 27))) ^  (((p2 << 14) | (p2 >>> 18)));

            final int pl0 = s0 ^ e0 ^ Xoodoo.RC[i];
            final int pl1 = s1 ^ e1;
            final int pl2 = s2 ^ e2;
            final int pl3 = s3 ^ e3;
            final int pl4 = s7 ^ e3;
            final int pl5 = s4 ^ e0;
            final int pl6 = s5 ^ e1;
            final int pl7 = s6 ^ e2;

            final int pw8 = s8 ^ e0;
            final int pw9 = s9 ^ e1;
            final int pw10 = s10 ^ e2;
            final int pw11 = s11 ^ e3;

            final int pl8 = (pw8 << 11) | (pw8 >>> 21);
            final int pl9 = (pw9 << 11) | (pw9 >>> 21);
            final int pl10 = (pw10 << 11) | (pw10 >>> 21);
            final int pl11 = (pw11 << 11) | (pw11 >>> 21);

            // χ step
            final int b0 = (~pl4) & pl8;
            final int b1 = (~pl5) & pl9;
            final int b2 = (~pl6) & pl10;
            final int b3 = (~pl7) & pl11;
            final int b4 = (~pl8) & pl0;
            final int b5 = (~pl9) & pl1;
            final int b6 = (~pl10) & pl2;
            final int b7 = (~pl11) & pl3;
            final int b8 = (~pl0) & pl4;
            final int b9 = (~pl1) & pl5;
            final int b10 = (~pl2) & pl6;
            final int b11 = (~pl3) & pl7;

            s0 = pl0 ^ b0;
            s1 = pl1 ^ b1;
            s2 = pl2 ^ b2;
            s3 = pl3 ^ b3;

            // ρ East step
            final int pe4 = pl4 ^ b4;
            final int pe5 = pl5 ^ b5;
            final int pe6 = pl6 ^ b6;
            final int pe7 = pl7 ^ b7;
            final int pe8 = pl10 ^ b10;
            final int pe9 = pl11 ^ b11;
            final int pe10 = pl8 ^ b8;
            final int pe11 = pl9 ^ b9;

            s4 = (pe4 << 1) | (pe4 >>> 31);
            s5 = (pe5 << 1) | (pe5 >>> 31);
            s6 = (pe6 << 1) | (pe6 >>> 31);
            s7 = (pe7 << 1) | (pe7 >>> 31);
            s8 = (pe8 << 8) | (pe8 >>> 24);
            s9 = (pe9 << 8) | (pe9 >>> 24);
            s10 = (pe10 << 8) | (pe10 >>> 24);;
            s11 = (pe11 << 8) | (pe11 >>> 24);;
        }
        outState
            .put(0, s0)
            .put(1, s1)
            .put(2, s2)
            .put(3, s3)
            .put(4, s4)
            .put(5, s5)
            .put(6, s6)
            .put(7, s7)
            .put(8, s8)
            .put(9, s9)
            .put(10, s10)
            .put(11, s11);
    }

    /**
     *
     * @param inState 48-byte ByteBuffer in little-endian format (as returned by getStateBuffer())
     * @param outState 48-byte ByteBuffer in little-endian format (as returned by getStateBuffer())
     */
    public static void permuteExternalState(StateSupplier inState, StateConsumer outState, int rounds) {
        int s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;

        s0 = inState.get(0);
        s1 = inState.get(1);
        s2 = inState.get(2);
        s3 = inState.get(3);
        s4 = inState.get(4);
        s5 = inState.get(5);
        s6 = inState.get(6);
        s7 = inState.get(7);
        s8 = inState.get(8);
        s9 = inState.get(9);
        s10 = inState.get(10);
        s11 = inState.get(11);

        for (int i = rounds - 1; i >= 0; --i) {

            // θ step, ρ West step and ι step
            final int p0 = s0 ^ s4 ^ s8;
            final int p1 = s1 ^ s5 ^ s9;
            final int p2 = s2 ^ s6 ^ s10;
            final int p3 = s3 ^ s7 ^ s11;

            final int e0 = (((p3 << 5) | (p3 >>> 27))) ^  (((p3 << 14) | (p3 >>> 18)));
            final int e1 = (((p0 << 5) | (p0 >>> 27))) ^  (((p0 << 14) | (p0 >>> 18)));
            final int e2 = (((p1 << 5) | (p1 >>> 27))) ^  (((p1 << 14) | (p1 >>> 18)));
            final int e3 = (((p2 << 5) | (p2 >>> 27))) ^  (((p2 << 14) | (p2 >>> 18)));

            final int pl0 = s0 ^ e0 ^ Xoodoo.RC[i];
            final int pl1 = s1 ^ e1;
            final int pl2 = s2 ^ e2;
            final int pl3 = s3 ^ e3;
            final int pl4 = s7 ^ e3;
            final int pl5 = s4 ^ e0;
            final int pl6 = s5 ^ e1;
            final int pl7 = s6 ^ e2;

            final int pw8 = s8 ^ e0;
            final int pw9 = s9 ^ e1;
            final int pw10 = s10 ^ e2;
            final int pw11 = s11 ^ e3;

            final int pl8 = (pw8 << 11) | (pw8 >>> 21);
            final int pl9 = (pw9 << 11) | (pw9 >>> 21);
            final int pl10 = (pw10 << 11) | (pw10 >>> 21);
            final int pl11 = (pw11 << 11) | (pw11 >>> 21);

            // χ step
            final int b0 = (~pl4) & pl8;
            final int b1 = (~pl5) & pl9;
            final int b2 = (~pl6) & pl10;
            final int b3 = (~pl7) & pl11;
            final int b4 = (~pl8) & pl0;
            final int b5 = (~pl9) & pl1;
            final int b6 = (~pl10) & pl2;
            final int b7 = (~pl11) & pl3;
            final int b8 = (~pl0) & pl4;
            final int b9 = (~pl1) & pl5;
            final int b10 = (~pl2) & pl6;
            final int b11 = (~pl3) & pl7;

            s0 = pl0 ^ b0;
            s1 = pl1 ^ b1;
            s2 = pl2 ^ b2;
            s3 = pl3 ^ b3;

            // ρ East step
            final int pe4 = pl4 ^ b4;
            final int pe5 = pl5 ^ b5;
            final int pe6 = pl6 ^ b6;
            final int pe7 = pl7 ^ b7;
            final int pe8 = pl10 ^ b10;
            final int pe9 = pl11 ^ b11;
            final int pe10 = pl8 ^ b8;
            final int pe11 = pl9 ^ b9;

            s4 = (pe4 << 1) | (pe4 >>> 31);
            s5 = (pe5 << 1) | (pe5 >>> 31);
            s6 = (pe6 << 1) | (pe6 >>> 31);
            s7 = (pe7 << 1) | (pe7 >>> 31);
            s8 = (pe8 << 8) | (pe8 >>> 24);
            s9 = (pe9 << 8) | (pe9 >>> 24);
            s10 = (pe10 << 8) | (pe10 >>> 24);;
            s11 = (pe11 << 8) | (pe11 >>> 24);;
        }
        outState
            .put(0, s0)
            .put(1, s1)
            .put(2, s2)
            .put(3, s3)
            .put(4, s4)
            .put(5, s5)
            .put(6, s6)
            .put(7, s7)
            .put(8, s8)
            .put(9, s9)
            .put(10, s10)
            .put(11, s11);
    }

    public void permute() {
        Xoodoo.permuteExternalState(this.state, this.state, this.rounds);
    }    
}
