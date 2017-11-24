package com.github.aelstad.keccakj.keyak.v2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.github.aelstad.keccakj.core.Keccak1600;

class Piston {

	Keccak1600 keccak1600;

	int rateSqueeze;
	int rateAbsorb;
	int offCrypt;
	int offInject;

	final static int EOM_OFF = 0;
	final static int CRYPT_END_OFF = 1;
	final static int INJECT_START_OFF = 2;
	final static int INJECT_END_OFF = 3;

	byte[] buf = new byte[200];

	InputStream isCrypt;
	InputStream isInject;

	int cryptLen;
	int injectLen;

	Piston(int rateSqueeze, int rateAbsorb) {
		this.keccak1600 = new Keccak1600(1600-rateSqueeze*8, 12);
		this.rateSqueeze = rateSqueeze;
		this.rateAbsorb = rateAbsorb;

		offCrypt = offInject = 0;
	}

	public int fillBuffer() throws IOException {
		int remaining=rateSqueeze - offCrypt;
		cryptLen=0;
		while(isCrypt != null && remaining > 0) {
			int read = isCrypt.read(buf, offCrypt, remaining);
			if(read > 0) {
				offCrypt += read;
				remaining -= read;
				cryptLen += read;
			} else if(read < 0) {
				isCrypt.close();
				isCrypt = null;
			}
		}
		if(cryptLen > 0) {
			offInject = rateSqueeze;
		}
		injectLen = 0;
		remaining = rateAbsorb - offInject;
		while(isInject != null && remaining > 0) {
			int read = isInject.read(buf, offInject, remaining);
			if(read > 0) {
				offInject += read;
				remaining -= read;
				injectLen += read;
			} else if(read < 0) {
				isInject.close();
				isInject = null;
			}
		}

		return cryptLen+injectLen;
	}

	public void transformBuffer(OutputStream os, boolean decrypt) throws IOException {
		if(cryptLen > 0) {
			keccak1600.setXorByte(rateAbsorb+CRYPT_END_OFF, (byte) (offCrypt));
		}
		keccak1600.setXorByte(rateAbsorb+INJECT_START_OFF, (byte) (offInject-injectLen));
		keccak1600.setXorByte(rateAbsorb+INJECT_END_OFF, (byte) (offInject));

		if(cryptLen > 0) {
			int off = offCrypt-cryptLen;
			if(decrypt) {
				keccak1600.unwrapBytes(off, buf, off, buf, off, cryptLen);
			} else {
				keccak1600.wrapBytes(off, buf, off, buf, off, cryptLen);
			}
			os.write(buf, off, cryptLen);
		}
		if(injectLen > 0) {
			int off = offInject-injectLen;
			keccak1600.setXorBytes(off, buf, off, injectLen);
		}

		offCrypt = offInject = 0;
		cryptLen = injectLen = 0;
	}

	public void spark() {
		keccak1600.permute();
	}

	public void handleTag(byte[] tag, int off, int len, boolean validate)
	{
		keccak1600.setXorByte(rateAbsorb+EOM_OFF, (byte) ((len == 0) ? 0xff : len));
		spark();
		if(len > 0) {
			if(validate) {
				keccak1600.validateBytes(0, tag, off, len);
			} else {
				keccak1600.getBytes(0, tag, off, len);
			}
		}
		offCrypt = (byte) len;
	}

	public void reset() {
		keccak1600.clear();
		offCrypt = 0;
		offInject = 0;
		cryptLen = injectLen = 0;
	}

	public void setStreams(InputStream isCrypt, InputStream isInject) {
		this.isCrypt = isCrypt;
		this.isInject = isInject;

	}
}
