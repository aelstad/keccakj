package com.github.aelstad.keccackj.provider;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.aelstad.keccackj.fips202.SHA3_224;
import com.github.aelstad.keccackj.fips202.SHA3_256;
import com.github.aelstad.keccackj.fips202.SHA3_384;
import com.github.aelstad.keccackj.fips202.SHA3_512;

public class TestKeccackjProvider {

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new KeccackjProvider());
	}
	
	@Test
	public void testSha3_224() throws Exception {
		Assert.assertTrue(Constants.SHA3_224.equals("SHA3-224"));
		Assert.assertTrue(MessageDigest.getInstance(Constants.SHA3_224, Constants.PROVIDER) instanceof SHA3_224);
	}
	
	@Test
	public void testSha3_256() throws Exception {
		Assert.assertTrue(Constants.SHA3_256.equals("SHA3-256"));
		Assert.assertTrue(MessageDigest.getInstance(Constants.SHA3_256, Constants.PROVIDER) instanceof SHA3_256);
	}
	
	@Test
	public void testSha3_384() throws Exception {
		Assert.assertTrue(Constants.SHA3_384.equals("SHA3-384"));
		Assert.assertTrue(MessageDigest.getInstance(Constants.SHA3_384, Constants.PROVIDER) instanceof SHA3_384);
	}
	
	@Test
	public void testSha3_512() throws Exception {
		Assert.assertTrue(Constants.SHA3_512.equals("SHA3-512"));
		Assert.assertTrue(MessageDigest.getInstance(Constants.SHA3_512, Constants.PROVIDER) instanceof SHA3_512);
	}

	@Test
	public void testKeccackRnd128() throws Exception {
		Assert.assertNotNull(SecureRandom.getInstance(Constants.KECCACK_RND128, Constants.PROVIDER));
	}

	@Test
	public void testKeccackRnd256() throws Exception {
		Assert.assertNotNull(SecureRandom.getInstance(Constants.KECCACK_RND256, Constants.PROVIDER));
		
		byte[] buf = new byte[1024];
		SecureRandom.getInstance(Constants.KECCACK_RND256, Constants.PROVIDER).nextBytes(buf);
	}

	
}
