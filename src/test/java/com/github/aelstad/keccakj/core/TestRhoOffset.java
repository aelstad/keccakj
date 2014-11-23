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
package com.github.aelstad.keccakj.core;

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccakj.core.Keccack1600;

public class TestRhoOffset {

	
	@Test
	public void testRhoOffsets() {
		int[] rhoffsets = Keccack1600.KeccakRhoOffsets;
		
		Assert.assertEquals(0, rhoffsets[Keccack1600.index(0,0)]);
		Assert.assertEquals(1, rhoffsets[Keccack1600.index(1,0)]);
		Assert.assertEquals(62, rhoffsets[Keccack1600.index(2,0)]);
		Assert.assertEquals(28, rhoffsets[Keccack1600.index(3,0)]);
		Assert.assertEquals(27, rhoffsets[Keccack1600.index(4,0)]);
		
		Assert.assertEquals(36, rhoffsets[Keccack1600.index(0,1)]);
		Assert.assertEquals(44, rhoffsets[Keccack1600.index(1,1)]);
		Assert.assertEquals(6, rhoffsets[Keccack1600.index(2,1)]);
		Assert.assertEquals(55, rhoffsets[Keccack1600.index(3,1)]);
		Assert.assertEquals(20, rhoffsets[Keccack1600.index(4,1)]);
		
		Assert.assertEquals(3, rhoffsets[Keccack1600.index(0,2)]);
		Assert.assertEquals(10, rhoffsets[Keccack1600.index(1,2)]);
		Assert.assertEquals(43, rhoffsets[Keccack1600.index(2,2)]);
		Assert.assertEquals(25, rhoffsets[Keccack1600.index(3,2)]);
		Assert.assertEquals(39, rhoffsets[Keccack1600.index(4,2)]);
		
		Assert.assertEquals(41, rhoffsets[Keccack1600.index(0,3)]);
		Assert.assertEquals(45, rhoffsets[Keccack1600.index(1,3)]);
		Assert.assertEquals(15, rhoffsets[Keccack1600.index(2,3)]);
		Assert.assertEquals(21,rhoffsets[Keccack1600.index(3,3)]);
		Assert.assertEquals(8, rhoffsets[Keccack1600.index(4,3)]);		

		Assert.assertEquals(18, rhoffsets[Keccack1600.index(0,4)]);
		Assert.assertEquals(2, rhoffsets[Keccack1600.index(1,4)]);
		Assert.assertEquals(61, rhoffsets[Keccack1600.index(2,4)]);
		Assert.assertEquals(56,rhoffsets[Keccack1600.index(3,4)]);
		Assert.assertEquals(14, rhoffsets[Keccack1600.index(4,4)]);		
	}
	
}
