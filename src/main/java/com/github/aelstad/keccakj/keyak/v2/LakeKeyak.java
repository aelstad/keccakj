package com.github.aelstad.keccakj.keyak.v2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;

public class LakeKeyak {
	private final static int KEYPACK_LENGTH = 40;
	private final static int SQUEEZE_BYTES = 1344/8;
	private final static int ABSORB_BYTES = 1536/8;

	Piston piston;

	public LakeKeyak() {
		piston = new Piston(SQUEEZE_BYTES, ABSORB_BYTES);
	}

	public void init(byte[] key, byte[] nonce, int nonceOff, int nonceLen, byte[] tag, int tagoff, boolean forget, boolean unwrap) throws IOException, InvalidKeyException
	{
		if(key == null || key.length > KEYPACK_LENGTH-2)
			throw new InvalidKeyException();

		piston.reset();

		PistonInitStreamBuilder pisb = new PistonInitStreamBuilder(key, KEYPACK_LENGTH, nonce, nonceOff, nonceLen);

		InputStream is = pisb.stream((byte) 1, (byte) 0);
		piston.setStreams(null, is);

		int len = 0;
		do {
			if(len > 0) {
				piston.spark();
			} else {
				len = piston.fillBuffer();
			}
			piston.transformBuffer(null, false);
			len = piston.fillBuffer();
		} while(len > 0);
		if(forget) {
			forget();
		}
		piston.handleTag(tag, tagoff, tag != null ? 16 : 0, unwrap);
	}

	void forget() throws IOException {
		byte[] tmp = new byte[32];
		piston.handleTag(tmp, 0, tmp.length, false);
		piston.setStreams(null, new ByteArrayInputStream(tmp));
		piston.fillBuffer();
		piston.transformBuffer(null, false);
	}

	void wrapOrUnwrap(InputStream in, InputStream ad, OutputStream out, byte[] tag, int tagoff, boolean forget, boolean unwrap) throws IOException
	{
		piston.setStreams(in, ad);
		int len = 0;
		do {
			if(len > 0) {
				piston.spark();
			} else {
				len = piston.fillBuffer();
			}
			piston.transformBuffer(out, unwrap);
			len = piston.fillBuffer();
		} while(len > 0);
		if(forget) {
			forget();
		}
		piston.handleTag(tag, tagoff, 16, unwrap);
	}

	public void unwrap(InputStream ciphertext, InputStream ad, OutputStream plaintext, byte[] tag, int tagoff, boolean forget) throws IOException
	{
		wrapOrUnwrap(ciphertext, ad, plaintext, tag, tagoff, forget, true);
	}

	public void wrap(InputStream ciphertext, InputStream ad, OutputStream plaintext, byte[] tag, int tagoff, boolean forget) throws IOException
	{
		wrapOrUnwrap(ciphertext, ad, plaintext, tag, tagoff, forget, false);
	}
}
