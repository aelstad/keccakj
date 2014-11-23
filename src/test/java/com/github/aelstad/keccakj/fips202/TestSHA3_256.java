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
package com.github.aelstad.keccakj.fips202;

import java.io.InputStream;
import java.util.List;

import org.junit.Test;

import com.github.aelstad.keccakj.fips202.SHA3_256;

public class TestSHA3_256 {
	
	@Test
	public void checkTestVectors() throws Exception {
		InputStream is = getClass().getResourceAsStream("/com/github/aelstad/keccackj/fips202/ShortMsgKAT_SHA3-256.txt");		
		
		KeccackDigestTestUtils kdtu = new KeccackDigestTestUtils();
		List<KeccackDigestTestUtils.DigestTest> tests = kdtu.parseTests(is);
		SHA3_256 sha = new SHA3_256();
		kdtu.runTests(tests, sha, sha.getDigestLength());
	}
}
