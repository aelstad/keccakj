package com.github.aelstad.keccackj.spi;

import com.github.aelstad.keccackj.provider.Constants;

public class Shake128Key extends RawKey {

	@Override
	public String getAlgorithm() {		
		return Constants.SHAKE128_STREAM_CIPHER;
	}

}
