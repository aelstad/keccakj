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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccackj.fips202.Shake128;

/**
 * Demonstrates stream encryption/decryption 
 */
public class TestStreamEncryption {
	
	@Test
	public void testIt() throws IOException {
		Shake128 shake128 = new Shake128();
		SecureRandom keyRandom = new SecureRandom();
		Random dataRandom = new Random();
		byte[] key = new byte[128];
		keyRandom.nextBytes(key);
		
		for(int i=8; i < 16384; ++i) {
			byte[] data = new byte[i];			
			byte[] nounce = new byte[128];
			keyRandom.nextBytes(nounce);
			dataRandom.nextBytes(data);
			
			shake128.getAbsorbStream().write(key);
			shake128.getAbsorbStream().write(nounce);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			FilterOutputStream fos = shake128.getTransformingSqueezeStream(bos);
			fos.write(data);
			fos.close();
			Assert.assertTrue(bos.size()==data.length);
			Assert.assertTrue(!Arrays.equals(data, bos.toByteArray()));
			
			byte[] encrypted = bos.toByteArray();
			
			shake128.reset();
			shake128.getAbsorbStream().write(key);
			shake128.getAbsorbStream().write(nounce);
			bos.reset();
			fos = shake128.getTransformingSqueezeStream(bos);
			fos.write(encrypted);
			fos.close();
			byte[] decrypted = bos.toByteArray();
			Assert.assertTrue(data != decrypted);
			Assert.assertTrue(Arrays.equals(decrypted, data));									
		}
		
		System.out.println("Encryption OK");

		
	}
}
