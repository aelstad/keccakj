package com.github.aelstad.keccackj.keyak;

import java.io.InputStream;
import java.util.List;

import org.junit.Test;

public class TestLakeKeyak {

	@Test
	public void checkTestVectors() throws Exception {
		InputStream is = getClass().getResourceAsStream("/com/github/aelstad/keccackj/keyak/LakeKeyak.txt");		
		
		KeyakTestUtils lktu = new KeyakTestUtils();
		List<KeyakTestUtils.KeyakTest> tests = lktu.parseTests(is);
		
		lktu.runTests(tests);
	}	
}
