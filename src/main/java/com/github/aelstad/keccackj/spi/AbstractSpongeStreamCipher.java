package com.github.aelstad.keccackj.spi;

import javax.crypto.ShortBufferException;

import com.github.aelstad.keccackj.core.KeccackSponge;
import com.github.aelstad.keccackj.io.BitOutputStream;

public abstract class AbstractSpongeStreamCipher extends AbstractCipher{
	
	@Override
	public void reset() {
		super.reset();
		getSponge().reset();
	}
	
	@Override
	protected void init() {
		KeccackSponge sponge = getSponge();
		BitOutputStream absorbStream = sponge.getAbsorbStream();
		absorbStream.write(getKey());	
		if(getNonce() != null)
			sponge.getAbsorbStream().write(getNonce());
		
		sponge.getAbsorbStream().close();
	}


	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int len, byte[] output, int outputOffset) throws ShortBufferException {				
		return getSponge().getSqueezeStream().transform(input, inputOffset, output, outputOffset, len);
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int offset, int len) {
		byte[] rv = new byte[len];
		getSponge().getSqueezeStream().transform(input, offset, rv, 0, len);
		
		return rv;
	}

	abstract KeccackSponge getSponge(); 
}
