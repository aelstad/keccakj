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

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccackj.core.KeccackStateUtils;
import com.github.aelstad.keccackj.core.KeccackStateUtils.StateOp;


public class TestKeccackStateUtils {
	
	long[] getState() {
		long[] rv = new long[20];
		for(int i=0; i < rv.length; ++i)
			rv[i] = ~0l;
		
		return rv;
	}

	@Test
	public void testIntOp()
	{
		for(int i=0; i < 20; ++i) {
			for(int j=0; j < 2; ++j) {
				long expected = ~0l ^ (0xffffffffl << j*32);
				long[] state = getState();				
				KeccackStateUtils.intOp(StateOp.ZERO, state, 2*i+j, 0, 0);
				Assert.assertTrue(state[i] == expected);
			}
		}
	}
	
	@Test
	public void testShortOp()
	{
		for(int i=0; i < 20; ++i) {
			for(int j=0; j < 4; ++j) {
				long expected = ~0l ^ (0xffffl << j*16);
				long[] state = getState();				
				KeccackStateUtils.shortOp(StateOp.ZERO, state, 4*i+j, (short) 0, (short) 0);
				Assert.assertTrue(state[i] == expected);
			}
		}
	}


	@Test
	public void testByteOp()
	{
		for(int i=0; i < 20; ++i) {
			for(int j=0; j < 8; ++j) {
				long expected = ~0l ^ (0xffl << j*8);
				long[] state = getState();				
				KeccackStateUtils.byteOp(StateOp.ZERO, state, 8*i+j, (byte) 0, (byte) 0);
				Assert.assertTrue(state[i] == expected);
			}
		}
	}
	
	@Test
	public void testBitOp()
	{
		for(int i=0; i < 20; ++i) {
			for(int j=0; j < 64; ++j) {
				long expected = ~0l ^ (1l << j);
				long[] state = getState();				
				KeccackStateUtils.bitOp(StateOp.ZERO, state, 64*i+j, false, true);
				Assert.assertTrue(state[i] == expected);
			}
		}
	}
	

}
