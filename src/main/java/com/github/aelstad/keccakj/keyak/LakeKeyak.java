/*
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
package com.github.aelstad.keccakj.keyak;

import java.security.InvalidKeyException;

import javax.crypto.AEADBadTagException;

import com.github.aelstad.keccakj.core.KeccakStateValidationFailedException;
import com.github.aelstad.keccakj.core.Keccak1600;

@Deprecated
public final class LakeKeyak {

	private int pos;
	private Keccak1600 keccak1600;
	
	private static final byte HEADER_MORE = 0;
	private static final byte TAG_NEXT = 1;
	private static final byte BODY_NEXT = 2;
	private static final byte BODY_MORE =  3;
	
	public LakeKeyak() {
		this.keccak1600 = new Keccak1600(252, 12);
	}

	public LakeKeyak(byte[] key, byte[] nounce) throws InvalidKeyException 
	{
		this();		
		init(key, nounce);
	}
	
	public void init(byte[] key, byte[] nounce) throws InvalidKeyException 
	{
		keccak1600.clear();
		byte keyPackLength = 30;	//240 bits keypack
		
		if(key == null || key.length < 16 || key.length > keyPackLength-2)
			throw new InvalidKeyException(); 
						
		keccak1600.setXorByte(pos, keyPackLength);
		++pos;
		keccak1600.setXorBytes(pos, key, 0, key.length);
		pos += key.length;
		keccak1600.setXorByte(pos, (byte) 1);		
		pos = keyPackLength;
		
		keccak1600.setXorByte(pos, (byte) 1);
		++pos;
		keccak1600.setXorByte(pos, (byte) 0);
		++pos;
		
		header(nounce, 0, nounce.length);		
	}
	
	public void header(byte[] buf, int off, int len) {
		while(len > 0) {
			int remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			if(remainingBytes == 0) {				
				keccak1600.pad(HEADER_MORE, 2, pos<<3);
				keccak1600.permute();
				pos = 0;
				remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			}
			
			int chunk =  Math.min(len, remainingBytes);
			keccak1600.setXorBytes(pos, buf, off, chunk);
			
			off += chunk;
			len -= chunk;
			pos += chunk;
		}	
	}
			
	public void endHeader(boolean hasBody) {
		keccak1600.pad(hasBody ? BODY_NEXT : TAG_NEXT, 2, pos<<3);
		
		keccak1600.permute();
		pos = 0;
	}
	
	public void bodyWrap(byte[] in, int inoff, byte[] out, int outoff, int len) {
		while(len > 0) {
			int remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			if(remainingBytes == 0) {				
				keccak1600.pad(BODY_MORE, 2, pos << 3);
				keccak1600.permute();
				pos = 0;
				remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			}
			
			int chunk =  Math.min(len, remainingBytes);
			keccak1600.wrapBytes(pos, out, outoff, in, inoff, chunk);
			inoff += chunk;
			outoff += chunk;
			len -= chunk;
			pos += chunk;
		}		
	}
	
	public void bodyUnwrap(byte[] in, int inoff, byte[] out, int outoff, int len) {
		while(len > 0) {
			int remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			if(remainingBytes == 0) {
				keccak1600.pad(BODY_MORE, 2, pos << 3);
				keccak1600.permute();
				pos = 0;
				remainingBytes = (keccak1600.remainingBits(pos<<3)-4)>>3;
			}
			
			int chunk =  Math.min(len, remainingBytes);
			keccak1600.unwrapBytes(pos, out, outoff, in, inoff, chunk);
			inoff += chunk;
			outoff += chunk;
			len -= chunk;
			pos += chunk;
		}		
	}
	
	
	public void endBody() {
		keccak1600.pad(TAG_NEXT, 2, pos<<3);
		keccak1600.permute();
		pos = 0;		
	}
	
	public void getTag(byte[] buf, int off, int len) {
		while(len > 0) {
			int chunk = Math.min(len, (keccak1600.getRateBits()-4)>>3);
			keccak1600.getBytes(0, buf, off, chunk);
			off += chunk;
			len -= chunk;
			if(len > 0) {
				keccak1600.pad(1);
				keccak1600.permute();
			}
		}						
	}
	
	public void validateTag(byte[] buf, int off, int len) throws AEADBadTagException {
		if(buf == null || off < 0 || (off+len) > buf.length)
			throw new AEADBadTagException();
		
		try {
			while(len > 0) {
				int chunk = Math.min(len, (keccak1600.getRateBits()-4)>>3);

				keccak1600.validateBytes(0, buf, off, chunk);
				off += chunk;
				len -= chunk;
				if(len > 0) {
					keccak1600.pad(1);
					keccak1600.permute();
				}
			}
		} catch(KeccakStateValidationFailedException ex) {
			throw new AEADBadTagException();
		}

	}
	

	
	
	public void wrap(byte[] ad, int adOff, int adLen, byte[] body, int bodyOff, int bodyLen, byte[] cipherOut, int cipherOff, byte[] tagOut, int tagOff, int tagLen)
	{
		if(ad != null && adLen > 0)		
			header(ad, adOff, adLen);
		
		if(body != null && bodyLen > 0) {
			endHeader(true);
			bodyWrap(body, bodyOff, cipherOut, cipherOff, bodyLen);
			endBody();			
		} else {
			endHeader(false);
		}
		if(tagOut != null) {
			getTag(tagOut, tagOff, tagLen);
		}
	}
	
	
	public void unwrap(byte[] ad, int adOff, int adLen, byte[] body, int bodyOff, int bodyLen, byte[] cipherOut, int cipherOff, byte[] tagIn, int tagOff, int tagLen) throws AEADBadTagException
	{
		if(ad != null && adLen > 0)		
			header(ad, adOff, adLen);
		
		if(body != null && bodyLen > 0) {
			endHeader(true);
			bodyUnwrap(body, bodyOff, cipherOut, cipherOff, bodyLen);
			endBody();			
		} else {
			endHeader(false);
		}
		if(tagIn != null) {
			validateTag(tagIn, tagOff, tagLen);
		}
	}
	
	
	public void forget() {
		keccak1600.pad(0);
		keccak1600.permute();
		
		keccak1600.zeroBytes(0, 168);
		keccak1600.pad(168<<3);		
		keccak1600.permute();
		
		pos = 0;
	}
	
	public byte[] getRateState() {
		byte[] rv = new byte[168];
		keccak1600.getBytes(0, rv, 0, rv.length);
		return rv;
	}
	
	
}
