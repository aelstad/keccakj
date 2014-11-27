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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


/**
 * An interface which resembles javax.crypto.Cipher, but does not have the 
 * JCA code signing requirement of Oracle's Java javax.crypto.Cipher. 
 * 
 * In Oracle/Sun Java Javax.crypto.Cipher's must to be signed by a 
 * JCA Code Signing Certification Authority.  This is a legal rather than 
 * technical way for Oracle/Sun to comply with the restrictions of use
 * and exporting of encryption in some countries.
 */
public interface CipherInterface
{
	void init(int opmode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException;

	void updateAAD(byte[] src);
	void updateAAD(byte[] src, int offset, int len);	
	void updateAAD(ByteBuffer src);
	
	byte[] update(byte[] input);
	byte[]	update(byte[] input, int inputOffset, int inputLen);
	int	update(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException;	
	int	update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;
	int	update(ByteBuffer input, ByteBuffer output) throws ShortBufferException;
	
	byte[]	doFinal() throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	byte[]	doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	byte[]	doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] input, int inputOffset, int inputLen, byte[] output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	int	doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
	int	doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;	

	byte[] wrap(Key key) throws InvalidKeyException, IllegalBlockSizeException;
	Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException;
}