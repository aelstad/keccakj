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

import java.io.FilterOutputStream;
import java.io.IOException;

import com.github.aelstad.keccackj.io.BitInputStream;
import com.github.aelstad.keccackj.io.BitOutputStream;

public class KeccackSponge {
	boolean squeezing;
	boolean absorbing;
	
	Keccack1600 keccack1600;
	
	int domainPaddingBitLength;
	byte[] domainPadding;
	
	private int ratePos;
	
	SqueezeStream squeezeStream;
	AbsorbStream absorbStream;

	
	private final class SqueezeStream extends BitInputStream {
		private boolean closed = true;
		
		public SqueezeStream() {
		}
		
		@Override
		public void close() {
			if(!closed) {				
				keccack1600.clear();
				closed = true;
				ratePos = 0;
			}
		}
		
		void open() {
			if(closed) {
				if(absorbStream != null) 
					absorbStream.close();
								
				ratePos = 0;
				closed = false;
			}
		}

		@Override
		public int read(byte[] b, int off, int len) {
			return readBits(b, ((int)off)<<3, ((int)len)<<3)>>3;
		}

		@Override
		public int read(byte[] b)  {
			return this.read(b, 0, b.length);
		}

		@Override
		public int readBits(byte[] bits, long bitOff, long bitLen) {
			open();
			
			while(bitLen > 0) {
				int remainingBits = keccack1600.remainingBits(ratePos);
				if(remainingBits <=  0) {
					keccack1600.permute();
					ratePos = 0;
					remainingBits = keccack1600.remainingBits(ratePos);
				}
				int chunk = (int) Math.min(bitLen, remainingBits);
				
				
				keccack1600.getBits(ratePos, bits, bitOff, chunk);
				
				ratePos += chunk;
				bitLen -= chunk;		
				bitOff += chunk;
			}			
			
			
			return 0;
		}

		@Override
		public int read() {
			open();
			
			byte[] buf = new byte[1];
			readBits(buf, 0, 8);
			
			return ((int) buf[0]) & 0xff;
		}
	}
	
	private final class AbsorbStream extends BitOutputStream {
		private boolean closed = false;

		@Override
		public void close() {
			if(!closed){
				writeBits(domainPadding, 0, domainPaddingBitLength);
				keccack1600.pad(ratePos);
				keccack1600.permute();
				closed = true;
				ratePos = 0;
			}
		}

		@Override
		public void writeBits(byte[] bits, long bitOff, long bitLen) {
			open();
			while(bitLen > 0) {
				int remainingBits = keccack1600.remainingBits(ratePos);
				if(remainingBits <=  0) {
					keccack1600.permute();
					ratePos = 0;
					remainingBits = keccack1600.remainingBits(ratePos);
				}
				int chunk = (int) Math.min(bitLen, remainingBits);
				
				
				keccack1600.setXorBits(ratePos, bits, bitOff, chunk);
				
				ratePos += chunk;
				bitLen -= chunk;		
				bitOff += chunk;
			}			
		}
		
		@Override
		public void write(byte[] b, int off, int len) {
			writeBits(b, ((int)off)<<3, ((int)len)<<3);
		}

		

		@Override
		public void write(int b) {
			writeBits(new byte[] { (byte) b }, 0, 8);
			
		}

		public void open() {
			if(closed) {
				if(squeezeStream != null) {
					squeezeStream.close();
				} else {
					keccack1600.clear();
					ratePos = 0;
				}
				closed = false;
			}							
			
		}

	}
	
	
	
	public KeccackSponge(int capacityInBits, byte[] domainPadding, int domainPaddingBitLength) {
		this.keccack1600 = new Keccack1600(capacityInBits);
		this.domainPadding = domainPadding;
		this.domainPaddingBitLength = domainPaddingBitLength;
		this.ratePos = 0;
	}
	
	public void reset() {
		if(absorbStream != null) {
			absorbStream.open();
		}
	}
	
	public BitInputStream getSqueezeStream() {
		if(squeezeStream == null) {
			squeezeStream = new SqueezeStream();
		} 
		squeezeStream.open();
		
		return squeezeStream;
		 
		
		
	}
	
	public BitOutputStream getAbsorbStream() {
		if(absorbStream == null) {
			absorbStream = new AbsorbStream();
		} 
		absorbStream.open();
		
		return absorbStream;
	}
	
	
	public java.io.FilterOutputStream getTransformingSqueezeStream(final java.io.OutputStream target) {
		return new FilterOutputStream(target) {

			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				byte[] buf = new byte[len];
				getSqueezeStream().read(buf);
				for(int i=0; i < buf.length; ++i) {
					buf[i] ^= b[i];
				}				
				target.write(buf);
			}

			@Override
			public void write(byte[] b) throws IOException {				
				this.write(b, 0, b.length);
			}

			@Override
			public void write(int b) throws IOException {
				target.write(b ^ getSqueezeStream().read());
			}

			@Override
			public void close() throws IOException {
				getSqueezeStream().close();
				super.close();				
			}
		};
		
	}

	
	public byte[] getRateBits(int boff, int len)
	{
		byte[] rv = new byte[(len+ (8 - len & 7)) >> 3];
		keccack1600.getBits(boff, rv, boff, len);
		return rv;
	}
	
	public int getRateBits() {
		return keccack1600.getRateBits();
	}
	

	
	
}	
	
 