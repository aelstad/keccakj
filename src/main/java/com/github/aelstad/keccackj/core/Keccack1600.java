/*
 * Copyright 2014 Amund Elstad. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.aelstad.keccackj.core;

import java.util.Arrays;

import com.github.aelstad.keccackj.core.KeccackStateUtils.StateOp;

/**
 * Java port of the reference implementation of Keccack-1600 permuation 
 * from https://github.com/gvanas/KeccakCodePackage
 *
 */
public final class Keccack1600 {		

	public Keccack1600()
	{
		this(256, 24);
	}
	
	public Keccack1600(int capacitityInBits) {
		this(capacitityInBits, NR_ROUNDS);
	}
	
	public Keccack1600(int capacityInBits, int rounds) {	
		this.capacitityBits = capacityInBits;
		this.rateBits = 1600-capacityInBits;
		this.rateBytes = rateBits >> 3;
		this.firstRound = NR_ROUNDS - rounds;
		
		clear();
	}
	
	byte byteOp(StateOp stateOp, int stateByteOff, byte out, byte in)
	{
		if(stateByteOff >= rateBytes)
			throw new IndexOutOfBoundsException();
		
		return KeccackStateUtils.byteOp(stateOp, state, stateByteOff, out, in); 		
	}
	
	
	void bytesOp(StateOp stateOp, int stateByteOff, byte[] out, int outpos, byte[] in, int inpos, int lenBytes)
	{
		if(stateByteOff+lenBytes > rateBytes)
			throw new IndexOutOfBoundsException();
		
		KeccackStateUtils.bytesOp(stateOp, state, stateByteOff, out, outpos, in, inpos, lenBytes);		
	}
	
	void bitsOp(StateOp stateOp, int stateBitOff, byte[] out, long outpos, byte[] in, long inpos, int lenBits)
	{
		if(stateBitOff+lenBits > rateBits)
			throw new IndexOutOfBoundsException();
		
		KeccackStateUtils.bitsOp(stateOp, state, stateBitOff, out, outpos, in, inpos, lenBits);		
	}
	
	
	public void getBytes(int stateByteOff, byte[] buf, int bufByteOff, int lenBytes) {
		bytesOp(StateOp.GET, stateByteOff, buf, bufByteOff, null, 0, lenBytes);
	}
	
	
	public void setBytes(int stateByteOff, byte[] buf, int bufByteOff, int lenBytes) {
		bytesOp(StateOp.SET, stateByteOff, null, 0, buf, bufByteOff, lenBytes);
	}
	
	public void setXorByte(int stateByteOff, byte val) {
		byteOp(StateOp.XOR_IN, stateByteOff, (byte) 0, val);
	}

	
	public void setXorBytes(int stateByteOff, byte[] buf, int bufByteOff, int lenBytes) {
		bytesOp(StateOp.XOR_IN, stateByteOff, null, 0, buf, bufByteOff, lenBytes);
	}
	
	
	public void zeroBytes(int stateByteOff, int lenBytes) {
		bytesOp(StateOp.ZERO, stateByteOff, null, 0, null, 0, lenBytes);
	}
	
	
	public void getBits(int stateBitOff, byte[] buf, long bufBitOff, int lenBits) {
		bitsOp(StateOp.GET, stateBitOff, buf, bufBitOff, null, 0, lenBits);		
	}
	
	public final void setBits(int stateBitOff, byte[] buf, long bufBitOff, int lenBits) {
		bitsOp(StateOp.SET, stateBitOff, null, 0, buf, bufBitOff, lenBits);
	}
	
	public final void setXorBits(int stateBitOff, byte[] buf, long bufBitOff, int lenBits) {
		bitsOp(StateOp.XOR_IN, stateBitOff, null, 0, buf, bufBitOff, lenBits);
	}
	
	
	public void zeroBits(int stateBitOff, int lenBits) {
		bitsOp(StateOp.ZERO, stateBitOff, null, 0, null, 0, lenBits);
	}
				
	
	public int remainingLongs(int longOff) {
		return remainingBits(longOff << 6) >> 6;
	}

	
	public int remainingBytes(int byteOff) {
		return remainingBits(byteOff << 3) >> 3;
	}
					
	public int remainingBits(int bitOff) {
		return rateBits - bitOff;
	}
	
	public void pad(int padBitPosition) 
	{
		int len = rateBits - padBitPosition;
		
		if(len < 0)
			throw new IndexOutOfBoundsException();
		
		if(len == 0) {
			permute();
			padBitPosition=0;
		}
		
		KeccackStateUtils.bitOp(StateOp.XOR_IN, state, padBitPosition, true, true);		
		
		if(len == 1) {
			permute();
		} 			
		
		KeccackStateUtils.bitOp(StateOp.XOR_IN, state, rateBits-1, true, true);
	}
			
	public void permute()
	{
		for(int i=firstRound; i < NR_ROUNDS; ++i) {
			theta();
			rho();
			pi();
			chi();
			iota(i);
		}		
	}
		
	public void clear() {
		Arrays.fill(state, 0l);		
	}
		
	
	final static int NR_ROUNDS = 24;
	final static int NR_LANES = 25;
		
	long[] state = new long[NR_LANES + 	// A
	                                NR_LANES +	// tempA
	                                5 		+ // tempC
	                                5		// tempD
	                               ];
	
	int rateBytes;
	int rateBits;
	int capacitityBits;
	int firstRound;
		
	final static int tempCidx(int idx) {
		return NR_LANES+NR_LANES+idx;
	}
	
	final static int tempDidx(int idx) {
		return NR_LANES+NR_LANES+5+idx;
	}
	
	final static int index(int x, int y) 
	{
		return (((x)%5)+5*((y)%5));
	}
	
	final static int aIdx(int x, int y) {
		return index(x,y);
	}
	
	final static int tempAIdx(int x, int y) {
		return NR_LANES+index(x,y);
	}
	
	final static long rol64(long l, int offset) {
		return (offset != 0) ?
				((l << offset) |  (l >>> (64-offset))) : l;
	}
	
	

	final static int[] KeccakRhoOffsets = new int[NR_LANES];
	final static long[] KeccackRoundConstants = new long [NR_ROUNDS];
	
	static {
		KeccakF1600_InitializeRoundConstants();
	    KeccakF1600_InitializeRhoOffsets();
	}
	
	final static void KeccakF1600_InitializeRoundConstants() 
	{
		 byte[] LFSRState= new byte[] { 0x01 } ;
		 int i, j, bitPosition;

		 for(i=0; i < NR_ROUNDS; i++) {
			 KeccackRoundConstants[i] = 0;
			 for(j=0; j<7; j++) {
				 bitPosition = (1<<j)-1; //2^j-1
				 if (LFSR86540(LFSRState))
					 KeccackRoundConstants[i] ^= 1l<<bitPosition;
			 }
		 }
	}
	
	final static boolean LFSR86540(byte[] LFSR)
	{		
	    boolean result = (LFSR[0] & 0x01) != 0;
	    if ((LFSR[0] & 0x80) != 0)
	        // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
	    	LFSR[0] = (byte) ((LFSR[0] << 1) ^ 0x71);
	    else
	    	LFSR[0] <<= 1;
	    return result;
	}	
	
	final static void KeccakF1600_InitializeRhoOffsets() 
	 {
		  int x, y, t, newX, newY;

		  KeccakRhoOffsets[index(0, 0)] = 0;
		  x = 1;
		  y = 0;
		  for(t=0; t<24; t++) {
			  KeccakRhoOffsets[index(x, y)] = ((t+1)*(t+2)/2) % 64;
			  newX = (0*x+1*y) % 5;
			  newY = (2*x+3*y) % 5;
			  x = newX;
			  y = newY;
		  }		
	 }
	 	 	
	final void theta()
	{
	    int x, y;
	    
	    for(x=0; x<5; x++) {
	        state[tempCidx(x)] = 0;
	        for(y=0; y<5; y++)
	            state[tempCidx(x)] ^= state[index(x, y)];
	    }
	    for(x=0; x<5; x++)
	        state[tempDidx(x)] = rol64(state[tempCidx((x+1)%5)], 1) ^ state[tempCidx((x+4)%5)];
	    for(x=0; x<5; x++)
	        for(y=0; y<5; y++)
	            state[aIdx(x, y)] ^= state[tempDidx(x)];
	}
		
	final void rho()
	{
	    int x, y;

	    for(x=0; x<5; x++) for(y=0; y<5; y++)
	        state[aIdx(x, y)] = rol64(state[aIdx(x, y)], KeccakRhoOffsets[index(x, y)]);
	}	
	
	final void pi()
	{
	    int x, y;
	    
	    for(x=0; x<5; x++) for(y=0; y<5; y++)
	        state[tempAIdx(x, y)] = state[index(x, y)];
	    for(x=0; x<5; x++) for(y=0; y<5; y++)
	        state[index(0*x+1*y, 2*x+3*y)] = state[tempAIdx(x, y)];
	}
	
	final void chi()
	{
	    int x, y;

	    for(y=0; y<5; y++) {
	        for(x=0; x<5; x++)
	            state[tempCidx(x)] = state[index(x, y)] ^ ((~state[index(x+1, y)]) & state[index(x+2, y)]);
	        for(x=0; x<5; x++)
	            state[index(x, y)] = state[tempCidx(x)];
	    }
	}
	
	void iota(int indexRound)
	{
	    state[index(0, 0)] ^= KeccackRoundConstants[indexRound];
	}

	public int getRateBits() {
		return this.rateBits;
	}

	public int getCapacitityBits() {
		return capacitityBits;
	}	
}
