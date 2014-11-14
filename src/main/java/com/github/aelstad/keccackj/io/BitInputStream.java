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
package com.github.aelstad.keccackj.io;

import java.io.InputStream;

public abstract class BitInputStream extends InputStream {		
	@Override
	public abstract void close();
	
	
	@Override
	public int read(byte[] b, int off, int len) {
		return readBits(b, ((long)off)<<3, ((long)len)<<3);
	}

	@Override
	public int read(byte[] b)  {
		return this.read(b, 0, b.length);
	}


	@Override
	public int read() {
		byte[] buf = new byte[1];
		readBits(buf, 0, 8);
		
		return ((int) buf[0]) & 0xff;		
	}


	public abstract int readBits(byte[] arg, long bitOff, long bitLen); 
}
