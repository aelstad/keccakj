package com.github.aelstad.keccakj.keyak.v2;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.util.Vector;

class PistonInitStreamBuilder {

	private byte[] keypack;

	private byte[] nonce;
	private int nonceOff;
	private int nonceLen;

	public PistonInitStreamBuilder(byte[] key, int keypackLength, byte[] nonce, int nonceOff, int nonceLen) {
		this.keypack = new byte[keypackLength];
		keypack[0] = (byte) keypackLength;
		System.arraycopy(key, 0, keypack, 1, key.length);
		keypack[key.length+1] = 1;
		this.nonce = nonce;
		this.nonceOff = nonceOff;
		this.nonceLen = nonceLen;
	}

	InputStream stream(final byte numPistons, final byte pistonIndex) {
		Vector<InputStream> streams = new Vector<InputStream>();
		streams.add(new ByteArrayInputStream(keypack));
		if(nonce != null) {
			streams.add(new ByteArrayInputStream(nonce, nonceOff, nonceLen));
		}
		streams.add(new ByteArrayInputStream(new byte[] {numPistons, pistonIndex}));

		return new SequenceInputStream(streams.elements());
	}
}
