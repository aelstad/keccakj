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
package com.github.aelstad.keccackj.fips202;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccackj.spi.Shake128Key;
import com.github.aelstad.keccackj.spi.Shake128StreamCipher;

/**
 * Demonstrates stream encryption/decryption 
 */
public class TestStreamEncryption {
	
	
	@Test
	public void testIt() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Shake128 shake128 = new Shake128();
		SecureRandom keyRandom = new SecureRandom();
		Random dataRandom = new Random();
		byte[] key = new byte[128];
		keyRandom.nextBytes(key);
		
		for(int i=8; i < 16384; ++i) {
			byte[] data = new byte[i];			
			byte[] nonce = new byte[128];
			keyRandom.nextBytes(nonce);
			dataRandom.nextBytes(data);
			
			shake128.getAbsorbStream().write(key);
			shake128.getAbsorbStream().write(nonce);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			FilterOutputStream fos = shake128.getTransformingSqueezeStream(bos);
			fos.write(data);
			fos.close();
			Assert.assertTrue(bos.size()==data.length);
			Assert.assertTrue(!Arrays.equals(data, bos.toByteArray()));
			
			byte[] encrypted = bos.toByteArray();
			
			shake128.reset();
			shake128.getAbsorbStream().write(key);
			shake128.getAbsorbStream().write(nonce);
			bos.reset();
			fos = shake128.getTransformingSqueezeStream(bos);
			fos.write(encrypted);
			fos.close();
			byte[] decrypted = bos.toByteArray();
			Assert.assertTrue(data != decrypted);
			Assert.assertTrue(Arrays.equals(decrypted, data));				
			
			// Using the SPI impl. getCipher not available unless Jar is signed	
			IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);
			Shake128Key shakeKey = new Shake128Key();
			shakeKey.setRaw(key);
			Shake128StreamCipher c  = new Shake128StreamCipher();
			c.init(Cipher.ENCRYPT_MODE, shakeKey, ivParameterSpec);
			byte[] encrypted2 = c.doFinal(data);
			Assert.assertArrayEquals(encrypted, encrypted2);
			c.init(Cipher.DECRYPT_MODE, shakeKey, ivParameterSpec);
			byte[] decrypted2 = c.doFinal(encrypted2);
			Assert.assertArrayEquals(decrypted2, data);
		}
		
		System.out.println("Encryption OK");

		
	}
}
