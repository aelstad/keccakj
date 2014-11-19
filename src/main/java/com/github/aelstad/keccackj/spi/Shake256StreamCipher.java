package com.github.aelstad.keccackj.spi;

import com.github.aelstad.keccackj.core.KeccackSponge;
import com.github.aelstad.keccackj.fips202.Shake256;

public class Shake256StreamCipher extends AbstractSpongeStreamCipher {

	private Shake256 sponge;

	@Override
	KeccackSponge getSponge() {
		if(sponge == null) {
			sponge = new Shake256();
		}
		return sponge;
	}

}
