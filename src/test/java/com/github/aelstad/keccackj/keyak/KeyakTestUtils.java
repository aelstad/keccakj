package com.github.aelstad.keccackj.keyak;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;

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
		byte[] nounce;
		
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
					nextTest.nounce = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("ciphertext")) {
					pc.ciphertext = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("plaintext")) {
					pc.plaintext = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("associated data")) {
					pc.ad = Hex.decodeHex(value.toCharArray());
				} else if(token.equalsIgnoreCase("tag")) {
					pc.tag = Hex.decodeHex(value.toCharArray());
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
			System.out.println("nonce: "+toHex(dt.nounce));
			
			wrapper.init(dt.key, dt.nounce);
			unwrapper.init(dt.key, dt.nounce);
			unwrapperFailing.init(dt.key, dt.nounce);
			
			for(TestCommand tc : dt.commands) {
				if(tc instanceof ForgetCommand) {
					wrapper.forget();
					unwrapper.forget();
					System.out.println("forget");
				} else if(tc instanceof PairCommand) {
					PairCommand pc = (PairCommand) tc;
					System.out.println("associated data: " + toHex(pc.ad));
					System.out.println("plaintext: " + toHex(pc.plaintext));
					System.out.println("ciphertext: " + toHex(pc.ciphertext));
					System.out.println("tag: " + toHex(pc.tag));
					
					byte[] wrapOut = new byte[pc.plaintext.length]; 
					byte[] tagOut = new byte[pc.tag.length];
					byte[] unwrapOut = new byte[pc.plaintext.length];
										
					wrapper.wrap(pc.ad, 0, pc.ad.length, pc.plaintext, 0, pc.plaintext.length, wrapOut, 0, tagOut, 0, tagOut.length);
					
					System.out.println("got ciphertext: " + toHex(wrapOut));
					System.out.println("got tag: " + toHex(tagOut));
					
					Assert.assertArrayEquals(wrapOut, pc.ciphertext);
					Assert.assertArrayEquals(tagOut, pc.tag);
					
					unwrapper.unwrap(pc.ad, 0, pc.ad.length, wrapOut, 0, wrapOut.length, unwrapOut, 0, tagOut, 0, tagOut.length);					
					Assert.assertArrayEquals(unwrapOut, pc.plaintext);
					
					if(wrapOut.length>0) {
						wrapOut[0] = (byte) (wrapOut[0]+1);
						KeyakTagValidationFailedException expected=null;
						try {
							unwrapperFailing.unwrap(pc.ad, 0, pc.ad.length, wrapOut, 0, wrapOut.length, unwrapOut, 0, tagOut, 0, tagOut.length);
						} catch(KeyakTagValidationFailedException ex) {
							expected = ex;
						}
						Assert.assertNotNull(expected);
					}
				}
				System.out.println();
			}
			
		}
	}
}
