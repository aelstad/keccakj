package com.github.aelstad.keccackj.spi;

import java.security.SecureRandomSpi;

import com.github.aelstad.keccackj.core.DuplexRandom;

/**
 * A cryptographic random implementation providing 128-bit 
 * security suitable for generating session keys.
 * 
 * Forgets the previous state after 2MB of random data.
 * 
 * Re-seeding with a small static seed also forgets the state.
 * 
 */
public final class KeccackRnd128 extends SecureRandomSpi {
	private final DuplexRandom dr = new DuplexRandom(253);
	
	private final static int FORGET_INTERVAL = 2*1024*1024;
	
	private int forgetCounter;
	
	public KeccackRnd128() {
		this.forgetCounter = FORGET_INTERVAL;
	}
	
	@Override
	protected byte[] engineGenerateSeed(int len) {
		byte[] rv = new byte[len];
		
		DuplexRandom.getSeedBytes(rv, 0, len);
		
		return rv;
		
	}

	@Override
	protected void engineNextBytes(byte[] buf) {
		dr.getBytes(buf, 0, buf.length);
		forgetCounter -= buf.length;
		if(forgetCounter <= 0)
		{
			dr.forget();
			forgetCounter -= FORGET_INTERVAL;
		}
	}

	@Override
	protected void engineSetSeed(byte[] seed) {
		dr.seed(seed, 0, seed.length);
	}

}
