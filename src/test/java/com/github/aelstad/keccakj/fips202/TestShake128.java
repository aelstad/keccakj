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

import com.github.aelstad.keccakj.fips202.Shake128;

public class TestShake128 {

	@Test
	public void checkTestVectors() throws Exception {
		InputStream is = KeccakDigestTestUtils.getResourceStreamInPackage(getClass(), "ShortMsgKAT_SHAKE128.txt");

		KeccakDigestTestUtils kdtu = new KeccakDigestTestUtils();
		List<KeccakDigestTestUtils.DigestTest> tests = kdtu.parseTests(is);
		Shake128 shake = new Shake128();
		kdtu.runTests(tests, shake);
	}

}
