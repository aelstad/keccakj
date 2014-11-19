package com.github.aelstad.keccackj.spi;

import java.security.SecureRandomSpi;

import com.github.aelstad.keccackj.core.DuplexRandom;

/**
 * A cryptographic random implementation providing 256-bit 
 * security suitable for generating long term keys.
 * 
 * Forgets the previous state after every call to 
 * nextBytes. 
 */
public final class KeccackRnd256 extends SecureRandomSpi {
	private final DuplexRandom dr = new DuplexRandom(509);
	
	@Override
	protected byte[] engineGenerateSeed(int len) {
		byte[] rv = new byte[len];
		
		DuplexRandom.getSeedBytes(rv, 0, len);
		
		return rv;
		
	}

	@Override
	protected void engineNextBytes(byte[] buf) {
		dr.getBytes(buf, 0, buf.length);
		dr.forget();
	}

	@Override
	protected void engineSetSeed(byte[] seed) {
		dr.seed(seed, 0, seed.length);
	}

}
