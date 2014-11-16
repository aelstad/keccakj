package com.github.aelstad.keccackj.keyak;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

import org.junit.Test;

public class TestLakeKeyak {

	@Test
	public void checkTestVectors() throws Exception {
		InputStream is = getClass().getResourceAsStream("/com/github/aelstad/keccackj/keyak/LakeKeyak.txt");		
		
		KeyakTestUtils lktu = new KeyakTestUtils();
		List<KeyakTestUtils.KeyakTest> tests = lktu.parseTests(is);
		
		lktu.runTests(tests);
	}
	
	@Test
	public void testPerformance() {
		int rounds = 128;
		Random r = new Random();
		SecureRandom sr = new SecureRandom();
		byte[] key = new byte[16];
		byte[] nounce = new byte[16];
		sr.nextBytes(key);
		sr.nextBytes(nounce);
		byte[] tag = new byte[16];
		byte[] body = new byte[2*1024*1024];
		r.nextBytes(body);
		
		LakeKeyak lkWrap = new LakeKeyak();
		lkWrap.init(key, nounce);
		lkWrap.wrap(null, 0, 0, body, 0, body.length, body, 0, tag, 0, tag.length);
		
		LakeKeyak lkUnwrap = new LakeKeyak();
		lkUnwrap.init(key, nounce);
		lkUnwrap.unwrap(null, 0, 0, body, 0, body.length, body, 0, tag, 0, tag.length);

		long startTs;
		long stopTs;
		long wrapTime = 0;
		long unwrapTime = 0;
		startTs = System.currentTimeMillis();
		for(int i=0; i < rounds; ++i) {
			lkWrap.wrap(null, 0, 0, body, 0, body.length, body, 0, tag, 0, tag.length);
			stopTs = System.currentTimeMillis();
			wrapTime += (stopTs-startTs);
			startTs = stopTs;
			lkUnwrap.unwrap(null, 0, 0, body, 0, body.length, body, 0, tag, 0, tag.length);
			stopTs = System.currentTimeMillis();
			unwrapTime += (stopTs-startTs);
			startTs = stopTs;
		}
		System.out.println("LakeKeyak inplace wrap performance "+((double) ((body.length*((long) rounds))*1000))/((double) wrapTime*1024*1024) + " MB/s");
		System.out.println("LakeKeyak inplace unwrap performance "+((double) ((body.length*((long) rounds))*1000))/((double) unwrapTime*1024*1024) + " MB/s");		
	}
}
