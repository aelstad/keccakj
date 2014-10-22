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

/**
 * Contains methods to manipulate Keccack 64-bit longs state using various-length primitvies
 * 
 */
final class KeccackStateUtils {
	
	public enum StateOp {
		ZERO, GET, SET, XOR_IN, XOR_OUT_XOR_IN, SET_OUT_XOR_IN;
		
		public boolean isIn() {
			return (this == StateOp.SET || this ==StateOp.XOR_IN || this ==StateOp.XOR_OUT_XOR_IN || this == StateOp.SET_OUT_XOR_IN); 
		}
		
		public boolean isOut() {
			return (this == StateOp.GET || this==StateOp.XOR_OUT_XOR_IN || this == StateOp.SET_OUT_XOR_IN); 
		}

	};
		
	public static long longOp(StateOp stateOp, long[] state, int pos, long out, long in) {
		long rv=out;
		long val = state[pos];
		switch (stateOp) {
		case ZERO:
			state[pos] = val^val;
			break;
		case GET:
			rv = val;
			break;
		case SET:
			state[pos] = in;
			break;
		case XOR_IN:
			val = val ^ in;
			state[pos] = val;
			break;
		case XOR_OUT_XOR_IN:
			rv ^= val;
			val = val ^ in;
			state[pos] = val;
		case SET_OUT_XOR_IN:
			rv = val;
			val = val ^ in;
			state[pos] = val;			
			break;
		}
		return rv;
	}
	
	public static int intOp(StateOp stateOp, long[] state, int pos, int out, int in) {
		long rv=out;
				
		long mask = 0x00000000ffffffffl;
		int shift = (pos & 1)<<5;
		int lpos = pos >> 1; 
		long lval = state[lpos];	
		long lin = in;
		long val = (lval >>> shift) & mask;
		switch (stateOp) {
		case ZERO:
			lval ^= (val << shift);
			state[lpos] = lval;
			break;
		case GET:
			rv = val;
			break;
		case SET:
			lval ^= (val << shift);
			lval |= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_IN:
			lval ^= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_OUT_XOR_IN:
			rv ^= val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		case SET_OUT_XOR_IN:
			rv = val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		}
		return (int) rv;
	}
	
	public static short shortOp(StateOp stateOp, long[] state, int pos, short out, short in) {
		long rv=out;
		
		long mask = 0x000000000000ffffl;
		int shift = (pos & 3)<<4;
		int lpos = pos >> 2; 
		long lval = state[lpos];	
		long lin = in;
		long val = (lval >>> shift) & mask;
		switch (stateOp) {
		case ZERO:
			lval ^= (val << shift);
			state[lpos] = lval;
			break;
		case GET:
			rv = val;
			break;
		case SET:
			lval ^= (val << shift);
			lval |= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_IN:
			lval ^= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_OUT_XOR_IN:
			rv ^= val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		case SET_OUT_XOR_IN:
			rv = val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		}
		return (short) rv;
	}
	
	public static byte byteOp(StateOp stateOp, long[] state, int pos, byte out, byte in) {
		long rv=out;
		
		long mask = 0x00000000000000ffl;
		int shift = (pos & 7)<<3;
		int lpos = pos >> 3; 
		long lval = state[lpos];	
		long lin = in;
		long val = (lval >>> shift) & mask;
		switch (stateOp) {
		case ZERO:
			lval ^= (val << shift);
			state[lpos] = lval;
			break;
		case GET:
			rv = val;
			break;
		case SET:
			lval ^= (val << shift);
			lval |= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_IN:
			lval ^= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_OUT_XOR_IN:
			rv ^= val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		case SET_OUT_XOR_IN:
			rv = val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		}
		return (byte) rv;
	}
	
	public static boolean bitOp(StateOp stateOp, long[] state, int pos, boolean bitOut, boolean bitIn) {
		long rv=bitOut ? 1 : 0;
		
		long mask = 1l;
		int shift = (pos & 63);
		int lpos = pos >> 6; 
		long lval = state[lpos];	
		long lin = bitIn==true ? 1 : 0;
		long val = (lval >>> shift) & mask;
		switch (stateOp) {
		case ZERO:
			lval ^= (val << shift);
			state[lpos] = lval;
			break;
		case GET:
			rv = val;
			break;
		case SET:
			lval ^= (val << shift);
			lval |= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_IN:
			lval ^= (lin << shift);
			state[lpos] = lval;
			break;
		case XOR_OUT_XOR_IN:
			rv ^= val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		case SET_OUT_XOR_IN:
			rv = val;
			lval ^= (lin << shift);
			state[lpos] = lval;
		}
		return rv==1;
	}
				
	public static void longsOp(StateOp stateOp, long[] state, int pos,
			long[] out, int outpos, long[] in, int inpos, int len) {
		boolean isOut = out != null && (stateOp == StateOp.GET || stateOp==StateOp.XOR_OUT_XOR_IN || stateOp== StateOp.SET_OUT_XOR_IN);
		boolean isIn = in != null && (stateOp == StateOp.SET || stateOp==StateOp.XOR_IN || stateOp==StateOp.XOR_OUT_XOR_IN || stateOp== StateOp.SET_OUT_XOR_IN);			
		while (len > 0) {
			long outvalue = isOut ? out[outpos] : 0;
			long invalue = isIn ? in[inpos] : 0;
			outvalue = longOp(stateOp, state, pos, outvalue, invalue); 
			if(isOut) {
				out[outpos] = outvalue;
			}
			pos++;
			inpos++;
			outpos++;
			--len;
		}
	}
	

	public static void intsOp(StateOp stateOp, long[] state, int pos,
			int [] out, int outpos, int[] in, int inpos, int len)
	{
		boolean isOut = out != null && stateOp.isOut();
		boolean isIn = in != null && stateOp.isIn();

		while(len > 0)
		{
			if((pos & 7) == 0 && len >= 2) {
				do {
					
					long lin=0;
					long lout=0;
					
					for(int i=0; isIn && i < 2; ++i ){
						lin  |= ((long) in[inpos]) << (i<<5); 
						lout >>>= 16;
						++inpos;
					}										
					
					lout = longOp(stateOp, state, inpos, lout, lin);
					
					for(int i=0; isOut && i < 2; ++i ){
						out[outpos] = (int) (lout & 0xffffffff);
						lout >>>= 16;
						++outpos;
					}					
				} while(len >= 2);
			} 
			if(len > 0) {
				int sin= isIn ? in[inpos] : 0;
				int sout = isOut ? out[outpos] : 0;
				if(isIn) {
					++inpos;
				}
				
				sout = intOp(stateOp, state, pos, sout, sin);
				if(isOut) {
					out[outpos] = sout;
					++outpos;
				}
			}
		}		
	}


	public static void shortsOp(StateOp stateOp, long[] state, int pos,
			short[] out, int outpos, short[] in, int inpos, int len)
	{
		boolean isOut = out != null && stateOp.isOut();
		boolean isIn = in != null && stateOp.isIn();

		while(len > 0)
		{
			if((pos & 3) == 0 && len >= 4) {
				do {					
					long lin=0;
					long lout=0;
					
					for(int i=0; isIn && i < 4; ++i ){
						lin  |= ((long) in[inpos]) << (i<<4); 
						lout >>>= 16;
						++inpos;
					}										
					
					lout = longOp(stateOp, state, inpos, lout, lin);
					
					for(int i=0; isOut && i < 4; ++i ){
						out[outpos] = (short) (lout & 0xffff);
						lout >>>= 16;
						++outpos;
					}					
				} while(len >= 4);
			} 
			if(len > 0) {
				short sin= isIn ? in[inpos] : 0;
				short sout = isOut ? out[outpos] : 0;
				if(isIn) {
					++inpos;
				}
				
				sout = shortOp(stateOp, state, pos, sout, sin);
				if(isOut) {
					out[outpos] = sout;
					++outpos;
				}
			}
		}
	}


	public static void bytesOp(StateOp stateOp, long[] state, int pos,
			byte[] out, int outpos, byte[] in, int inpos, int len)
	{			
		bitsOp(stateOp, state, pos<<3, out, ((long) outpos)<<3, in, ((long)inpos)<<3, len <<3);
	}


	public static void bitsOp(StateOp stateOp, long[] state, int pos,
			byte[] out, long outpos, byte[] in, long inpos, int len) 
	{

 		boolean isOut = out != null && stateOp.isOut();
		boolean isIn = in != null && stateOp.isIn();

		while(len > 0) {
			int bitoff = pos & 63;
			int bitlen = Math.min(64 - bitoff, len);
			
			if(stateOp == StateOp.ZERO && bitlen < 64) {
				long mask = (~0l << bitoff) & (~0l >>> (64-bitlen-bitoff) );
				long val = state[pos >> 6];
				val ^= val & mask;
				state[pos>>6] = val;
				pos += bitlen;
				len -= bitlen;
				continue;
			}

			// if we don't replace all the bits -> fetch existing values
			long lin= stateOp == StateOp.SET && bitlen < 64 ? state[pos >> 6] : 0;
			long lout=0;

			if(isIn) {
				// set bits in lin 
				lin = setBitsInLong(in, inpos, lin, bitoff, bitlen);
				inpos+= bitlen;
			}
				
			lout = longOp(stateOp, state, pos >> 6, lout, lin);
			if(isOut) {
				// set bits in out
				setBitsFromLong(out, outpos, lout, bitoff, bitlen);
				outpos += bitlen;
			}					
			pos += bitlen;
			len -= bitlen;
		}			
	}
	
	static long setBitsInLong(byte[] src, long srcoff,  long l, int off, int len)
	{
		int shift=off;
		// clear bits in l
		long mask = ~(~0l << len);
		mask = mask << off;
		l ^= l & mask;
		while(len > 0) {
			int bitoff = (int) (srcoff & 7);
			int srcByteOff = (int) (srcoff >> 3);
			if(bitoff==0 && len >= 8) {
				do {
					// aligned byte
					long val = ((long )(src[srcByteOff])) &0xffl; 

					l |= val << shift;
					shift += 8;
					len -= 8;
					srcoff += 8;
					++srcByteOff;
				} while(len >= 8);			
			} else {
				int bitlen = Math.min(8 - bitoff, len);
				
				byte valmask = (byte) ((0xff << bitoff) & (0xff >>> (8-bitlen-bitoff)));
				long lval = ((long )(src[srcByteOff] & valmask)) & 0xffl;
				lval >>>= bitoff;

				l |= lval << shift;
				
				srcoff += bitlen;
				len -= bitlen;
				shift += bitlen;								
			}
		}		
		return l;		 
	}
	
	static void setBitsFromLong(byte[] dst, long dstoff,  long l, int off, int len)
	{
		int shift=off;
		while(len > 0) {
			int bitoff = (int) dstoff & 7;
			int dstByteOff = (int) (dstoff >> 3);

			if(bitoff==0 && len >= 8) {
				do {
					// aligned byte
					dst[dstByteOff] = (byte) ((l >>> shift) & 0xff);
					shift += 8;
					len -= 8;
					dstoff += 8;
					++dstByteOff;
				} while(len >= 8);			
			} else {				
				int bitlen = Math.min(8 - bitoff, len);
				byte mask = (byte) ((0xff << bitoff) & (0xff >>> (8-bitlen-bitoff)));				
				byte val = dst[dstByteOff];
				long lval = (l >>> shift); 
				
				val ^= val & mask;
				val |= (lval<<bitoff) & mask;
				
				dst[dstByteOff] = val;
												
				dstoff += bitlen;
				len -= bitlen;
				shift += bitlen;				
			}
		}		
	}	
	
}
