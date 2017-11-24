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
package com.github.aelstad.keccakj.keyak;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;

import com.github.aelstad.keccakj.spi.LakeKeyakCipher;
import com.github.aelstad.keccakj.spi.LakeKeyakKey;

public class KeyakTestUtils {
	public interface TestCommand {}
	public static class ForgetCommand implements TestCommand {}
	public static class PairCommand implements TestCommand {
		byte[] ad = new byte[0];
		byte[] plaintext = new byte[0];
		byte[] ciphertext = new byte[0];
		byte[] tag = new byte[0];
	}

	public static class KeyakTest {
		byte[] key;
		byte[] nonce;

		List<TestCommand> commands = new ArrayList<TestCommand>();
	}

	public List<KeyakTest> parseTests(InputStream is) throws Exception
	{
		List<KeyakTest> rv = new ArrayList<KeyakTest>();

		BufferedReader br = new BufferedReader(new InputStreamReader(is));
		String line;

		KeyakTest nextTest = new KeyakTest();
		PairCommand pc = new PairCommand();
		while((line = br.readLine()) != null) {
			String token=null;
			String value=null;

			if(line.contains("forget")) {
				nextTest.commands.add(new ForgetCommand());
				continue;
			} else if(line.contains(":")) {
				String[] splitted = line.split(":");
				token = splitted[0].trim();
				value = splitted.length > 1 ? splitted[1].replace(" ", "") : null;
			} else {
				continue;
			}
			if(token.equalsIgnoreCase("initialize with") && nextTest.commands.size()>0) {
				rv.add(nextTest);
				nextTest= new KeyakTest();
			}

			if(token != null && value != null && token.length() > 0 && value.length() > 0) {
				if(token.equalsIgnoreCase("key")) {
					nextTest.key = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("nonce")) {
					nextTest.nonce = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("ciphertext")) {
					pc.ciphertext = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("plaintext")) {
					pc.plaintext = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("associated data")) {
					pc.ad = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("tag")) {
					pc.tag = Hex.decodeHex(value.toCharArray());
					if(pc.tag.length > 16) {
						byte[] tmp = pc.tag;
						pc.tag = new byte[16];
						System.arraycopy(tmp, 0, pc.tag, 0, 16);
					}

					nextTest.commands.add(pc);
					pc = new PairCommand();
				}
			}
		}
		if(nextTest.commands.size() > 0)
			rv.add(nextTest);

		return rv;
	}

	public static String toHex(byte[] buf) {
		if(buf==null)
			return "";
		return new String(Hex.encodeHex(buf));
	}

	public void runTests(List<KeyakTest> tests)
		throws Exception
	{
		LakeKeyak wrapper = new LakeKeyak();
		LakeKeyak unwrapper = new LakeKeyak();
		LakeKeyak unwrapperFailing = new LakeKeyak();

		for(KeyakTest dt : tests) {
			System.out.println("initialize with:");
			System.out.println("key: "+toHex(dt.key));
			System.out.println("nonce: "+toHex(dt.nonce));

			wrapper.init(dt.key, dt.nonce);
			unwrapper.init(dt.key, dt.nonce);
			unwrapperFailing.init(dt.key, dt.nonce);

			LakeKeyakCipher lkEncryptingCipher = new LakeKeyakCipher();
			lkEncryptingCipher.init(Cipher.ENCRYPT_MODE, new LakeKeyakKey(dt.key), new IvParameterSpec(dt.nonce));

			LakeKeyakCipher lkDecryptingCipher = new LakeKeyakCipher();
			lkDecryptingCipher.init(Cipher.DECRYPT_MODE, new LakeKeyakKey(dt.key), new IvParameterSpec(dt.nonce));

			LakeKeyakCipher lkDecryptingFailing = new LakeKeyakCipher();
			lkDecryptingFailing.init(Cipher.DECRYPT_MODE, new LakeKeyakKey(dt.key), new IvParameterSpec(dt.nonce));

			for(TestCommand tc : dt.commands) {
				if(tc instanceof ForgetCommand) {
					System.out.println("forget");
					lkEncryptingCipher.forget();
					lkDecryptingCipher.forget();
				} else if(tc instanceof PairCommand) {
					PairCommand pc = (PairCommand) tc;
					System.out.println("associated data: " + toHex(pc.ad));
					System.out.println("plaintext: " + toHex(pc.plaintext));
					System.out.println("ciphertext: " + toHex(pc.ciphertext));
					System.out.println("tag: " + toHex(pc.tag));

					byte[] wrapOut = new byte[pc.plaintext.length];
					byte[] tagOut = new byte[pc.tag.length];

					lkEncryptingCipher.updateAAD(pc.ad);
					byte[] encrypted = lkEncryptingCipher.doFinal(pc.plaintext);
					Assert.assertTrue(encrypted.length == pc.plaintext.length + 16);

					System.arraycopy(encrypted, 0, wrapOut, 0, pc.plaintext.length);
					System.arraycopy(encrypted, encrypted.length-16, tagOut, 0, 16);

					System.out.println("got ciphertext: " + toHex(wrapOut));
					System.out.println("got tag: " + toHex(tagOut));

					Assert.assertArrayEquals(wrapOut, pc.ciphertext);
					Assert.assertArrayEquals(tagOut, pc.tag);

					lkDecryptingCipher.updateAAD(pc.ad);
					byte[] decrypted = lkDecryptingCipher.doFinal(encrypted);
					Assert.assertArrayEquals(decrypted, pc.plaintext);

					lkDecryptingFailing.updateAAD(pc.ad);
					AEADBadTagException expected=null;
					try {
						byte[] decryptedFailing = lkDecryptingFailing.doFinal(new byte[16]);
					} catch(AEADBadTagException ex) {
						expected = ex;
					}
					Assert.assertNotNull(expected);

					lkDecryptingFailing = new LakeKeyakCipher();
					lkDecryptingFailing.init(Cipher.DECRYPT_MODE, new LakeKeyakKey(dt.key), new IvParameterSpec(dt.nonce));

				}
				System.out.println();
			}

		}
	}
}
