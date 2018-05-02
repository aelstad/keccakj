package com.github.aelstad.keccakj.core;

import java.security.MessageDigest;

import com.github.aelstad.keccakj.io.BitInputStream;
import com.github.aelstad.keccakj.io.BitOutputStream;

public abstract class AbstractKeccakMessageDigest extends MessageDigest {

	KeccakSponge keccakSponge;
	BitOutputStream absorbStream;
	int digestLength;

	/**
	 * Security level in bits is min(capacity/2,digestLength*8).
	 *
	 * @param algorithm Algorithm name
	 * @param capacityInBits Keccack capacity in bits. Must be a multiple of 8.
	 * @param digestLength Length of digest in bytes
	 * @param domainPadding Domain padding value
	 * @param domainPaddingBitLength Domain padding bits
	 */
	public AbstractKeccakMessageDigest(String algorithm, int capacityInBits, int digestLength, byte domainPadding, int domainPaddingBitLength)
	{
		super(algorithm);
		this.keccakSponge = new KeccakSponge(capacityInBits, domainPadding, domainPaddingBitLength);

		this.absorbStream = keccakSponge.getAbsorbStream();
		this.digestLength = digestLength;
	}

	@Override
	protected byte[] engineDigest() {
		absorbStream.close();

		byte[] rv = new byte[digestLength];
		BitInputStream bis = keccakSponge.getSqueezeStream();
		bis.read(rv);
		bis.close();

		return rv;
	}

	@Override
	protected void engineReset() {
		keccakSponge.reset();
	}

	public void engineUpdateBits(byte[] bits, long bitOff, long bitLength)
	{
		absorbStream.writeBits(bits, bitOff, bitLength);
	}

	@Override
	protected void engineUpdate(byte input) {
		absorbStream.write(((int) input));
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		engineUpdateBits(input, ((long) offset)<<3, ((long)len)<<3);
	}

	public byte[] getRateBits(int boff, int len)
	{
		return keccakSponge.getRateBits(boff, len);
	}

	public int getRateBits() {
		return keccakSponge.getRateBits();
	}

	@Override
	protected int engineGetDigestLength() {
		return digestLength;
	}

	public KeccakSponge getSponge() {
		return keccakSponge;
	}
}
