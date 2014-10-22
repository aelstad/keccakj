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
package com.github.aelstad.keccackj.core;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccackj.core.Keccack1600;

public class TestRoundConstants {
	public static final long[] EXPECTED = new long[] {
			0x0000000000000001l,		
			0x0000000000008082l,	
			0x800000000000808Al,	
			0x8000000080008000l,
			0x000000000000808Bl,
			0x0000000080000001l,
			0x8000000080008081l,
			0x8000000000008009l,
			0x000000000000008Al,	
			0x0000000000000088l,
			0x0000000080008009l,
			0x000000008000000Al,			
			0x000000008000808Bl,
			0x800000000000008Bl,
			0x8000000000008089l,
			0x8000000000008003l,
			0x8000000000008002l,
			0x8000000000000080l,
			0x000000000000800Al,
			0x800000008000000Al,
			0x8000000080008081l,
			0x8000000000008080l,
			0x0000000080000001l,
			0x8000000080008008l
	};
	

	@Test
	public void testRoundConstants() 
	{
		Assert.assertTrue(Arrays.equals(Keccack1600.KeccackRoundConstants, EXPECTED));
	}
}
