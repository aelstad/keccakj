package com.github.aelstad.keccackj.spi;

import java.security.InvalidKeyException;


public final class LakeKeyakKey extends RawKey {		
	public LakeKeyakKey() {
		super();
	}
	
	public LakeKeyakKey(byte[] rawKey) throws InvalidKeyException {
		super(rawKey);
	}
	
	@Override
	public String getAlgorithm() {
		return "LakeKeyak";
	}

	@Override
	public int getMaxKeyLength() {
		return 30;
	}
	
	
}
