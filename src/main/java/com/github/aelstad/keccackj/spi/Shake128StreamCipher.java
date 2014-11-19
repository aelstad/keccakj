package com.github.aelstad.keccackj.spi;

import com.github.aelstad.keccackj.core.KeccackSponge;
import com.github.aelstad.keccackj.fips202.Shake128;

public final class Shake128StreamCipher extends AbstractSpongeStreamCipher {
	private Shake128 sponge;

	@Override
	KeccackSponge getSponge() {
		if(sponge == null) {
			sponge = new Shake128();
		}
		return sponge;
	}

}
