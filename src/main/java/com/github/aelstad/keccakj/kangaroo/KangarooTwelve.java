package com.github.aelstad.keccakj.kangaroo;

import java.security.MessageDigest;

import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.io.BitInputStream;
import com.github.aelstad.keccakj.io.BitOutputStream;

public class KangarooTwelve extends MessageDigest {
	private final static int CHUNK_SIZE=8192;

	private final static byte[] PAD_FIRST_LONG = new byte[]
	{ (byte) 0x3, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,(byte) 0, (byte) 0 };
	private final static byte[] PAD_LAST_LONG = new byte[] {  (byte) 0xFF, (byte) 0xFF };

	private final static byte[] DOMAIN_PAD_SHORT = new byte[] { 3 };
	private final static byte[] DOMAIN_PAD_LONG = new byte[] { 2 };

	private KeccakSponge main = new KeccakSponge(12, 256, (byte) 0, 0);
	private KeccakSponge inner = new KeccakSponge(12, 256, (byte) 0x3, 3);

	private KeccakSponge current;

	private byte[] salt;

	int off=0;
	long chunk=0;

	private int outputLen;

	void flip() {
		if(off == 0) {
			return;
		}
		if(chunk > 0) {
			BitOutputStream bos = main.getAbsorbStream();
			if(chunk == 1) {
				bos.write(PAD_FIRST_LONG);
			}
			inner.getAbsorbStream().close();
			BitInputStream bis = inner.getSqueezeStream();
			byte[] cv = new byte[32];
			bis.read(cv);
			bis.close();
			inner.reset();
			bos.write(cv);
		}
		++chunk;
		current = inner;
		off = 0;
	}

	public KangarooTwelve(int outputLen, byte[] diversifier) {
		super("");
		this.outputLen = outputLen;
		setSalt(diversifier);
		reset();
	}

	private void setSalt(byte[] salt) {
		byte[] buf = new byte[9];
		int saltlen = salt != null ? salt.length : 0;
		int len = rightEncode(saltlen, buf);
		this.salt = new byte[saltlen + len];
		if(saltlen > 0) {
			System.arraycopy(salt, 0, this.salt, 0, saltlen);
		}
		System.arraycopy(buf, (buf.length-len), this.salt, saltlen, len);
	}

	@Override
	protected void engineUpdate(byte input) {
		if(off == CHUNK_SIZE) {
			flip();
		}
		current.getAbsorbStream().write((byte) input);

	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		while(len > 0) {
			int left = CHUNK_SIZE - off;

			if(left == 0) {
				flip();
			} else {
				int copyLen = Math.min(left, len);
				current.getAbsorbStream().write(input, offset, copyLen);
				len -= copyLen;
				offset += copyLen;
				off += copyLen;
			}
		}

	}

	int rightEncode(long l, byte[] buf) {
		int i=buf.length-2;
		int len=0;
		while(l > 0) {
			buf[i] = (byte) l;
			l >>= 8;
			--i;
			++len;
		}
		buf[buf.length-1] = (byte) len;

		return (len+1);
	}

	@Override
	protected byte[] engineDigest() {
		engineUpdate(salt, 0, salt.length);
		BitOutputStream bos = main.getAbsorbStream();
		if(chunk > 1)
		{
			flip();
			byte[] buf = new byte[9];
			int len = rightEncode(chunk-1, buf);
			bos.write(buf, buf.length-len, len);
			bos.write(PAD_LAST_LONG);
			bos.writeBits(DOMAIN_PAD_LONG, 0, 2);
		} else {
			bos.writeBits(DOMAIN_PAD_SHORT, 0, 2);
		}
		bos.close();
		BitInputStream bis = main.getSqueezeStream();
		byte[] rv = new byte[outputLen];
		bis.read(rv);
		bis.close();

		reset();

		return rv;
	}

	@Override
	protected void engineReset() {
		main.reset();
		inner.reset();
		off = 0;
		chunk = 0;
		current = main;
	}
}
