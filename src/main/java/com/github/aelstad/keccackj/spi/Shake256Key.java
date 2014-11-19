package com.github.aelstad.keccackj.spi;

import com.github.aelstad.keccackj.provider.Constants;

public class Shake256Key extends RawKey {

	@Override
	public String getAlgorithm() {
		return Constants.SHAKE256_STREAM_CIPHER;
	}

}
