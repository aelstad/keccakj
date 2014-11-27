/*
 * Copyright 2014 Amund Elstad. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.aelstad.keccakj.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * Wraps a javax.crypto.Cipher and provides a com.github.aelstad.keccackj.CipherInterface 
 *
 */
public final class CipherAdapter implements CipherInterface {

	private Cipher cipher;

	public CipherAdapter(Cipher cipher) {
		this.cipher = cipher;
	}

	@Override
	public void init(int opmode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		cipher.init(opmode, key, params);		
	}

	@Override
	public void updateAAD(byte[] src) {
		cipher.updateAAD(src);		
	}

	@Override
	public void updateAAD(byte[] src, int offset, int len) {
		cipher.updateAAD(src, offset, len);		
	}

	@Override
	public void updateAAD(ByteBuffer src) {
		cipher.updateAAD(src);		
	}

	@Override
	public byte[] update(byte[] input) {
		return cipher.update(input);
	}

	@Override
	public byte[] update(byte[] input, int inputOffset, int inputLen) {
		return cipher.update(input, inputOffset, inputLen);
	}

	@Override
	public int update(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException {
		return cipher.update(input, inputOffset, inputLen, output);
	}

	@Override
	public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
		return cipher.update(input, inputOffset, inputLen, output, outputOffset);
	}

	@Override
	public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
		return cipher.update(input, output);
	}

	@Override
	public byte[] doFinal() throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal();
	}

	@Override
	public byte[] doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(input);
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		return cipher.doFinal(output, outputOffset);
	}

	@Override
	public byte[] doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException,
			BadPaddingException {
		return cipher.doFinal(input, inputOffset, inputLen);
	}

	@Override
	public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(input, inputOffset, inputLen, output);
	}

	@Override
	public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
	}

	@Override
	public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		return cipher.doFinal(input, output);
	}

	@Override
	public byte[] wrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
		return cipher.wrap(key);
	}

	@Override
	public Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException,
			NoSuchAlgorithmException {
		return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
	}	
}
