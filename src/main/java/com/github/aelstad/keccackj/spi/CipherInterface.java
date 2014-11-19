package com.github.aelstad.keccackj.spi;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


/**
 * javax.security.Cipher's can only be instantiated from signed jars which makes testing difficult.
 *
 * Helper interface which resembles javax.Security.Cipher
 */
public interface CipherInterface
{
	byte[]	doFinal() throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	byte[]	doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	byte[]	doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	int	doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	
	void init(int opmode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException;
	
	Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException;
	
	byte[] update(byte[] input);

	byte[]	update(byte[] input, int inputOffset, int inputLen);

	int	update(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException;
	
	int	update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;

	int	update(ByteBuffer input, ByteBuffer output) throws ShortBufferException;

	void updateAAD(byte[] src);

	void updateAAD(byte[] src, int offset, int len);
	
	void updateAAD(ByteBuffer src);
	
	byte[] wrap(Key key) throws InvalidKeyException, IllegalBlockSizeException;

}