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

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccackj.core.Keccack1600;

public class TestPermutation 
{	
	String hexWordsToHexBytes(String hexWords) {
		StringBuilder rv = new StringBuilder();
		byte[] buf = new byte[8]; 
		for(String word : hexWords.split(" ")) {
			if(word.trim().isEmpty())
				continue;			
			long l = new BigInteger(word, 16).longValue();
			for(int i = 0; i < 8; ++i) {
				buf[i] = (byte) ((l >>> (8*i)) & 0xFF);						
			}
			rv.append(org.apache.commons.codec.binary.Hex.encodeHex(buf));
		}
		return rv.toString();
	}
	
	byte[] getTetaBytes() throws Exception
	{
		String inHexBytes ="E7 DD E1 40 79 8F 25 F1 8A 47 C0 33 F9 CC D5 84 EE A9 5A A6 1E 26 98 D5 4D 49 80 6F 30 47 15 BD 57 D0 53 62 05 4E 28 8B D4 6F 8E 7F 2D A4 97 FF C4 47 46 A4 A0 E5 FE 90 76 2E 19 D6 0C DA 5B 8C 9C 05 19 1B F7 A6 30 AD 64 FC 8F D0 B7 5A 93 30 35 D6 17 23 3F A9 5A EB 03 21 71 0D 26 E6 A6 A9 5F 55 CF DB 16 7C A5 81 26 C8 47 03 CD 31 B8 43 9F 56 A5 11 1A 2F F2 01 61 AE D9 21 5A 63 E5 05 F2 70 C9 8C F2 FE BE 64 11 66 C4 7B 95 70 36 61 CB 0E D0 4F 55 5A 7C B8 C8 32 CF 1C 8A E8 3E 8C 14 26 3A AE 22 79 0C 94 E4 09 C5 A2 24 F9 41 18 C2 65 04 E7 26 35 F5 16 3B A1 30 7F E9 44 F6 75 49 A2 EC 5C 7B FF F1 EA";

		inHexBytes = inHexBytes.replace(" ", "");
		byte[] inBytes = org.apache.commons.codec.binary.Hex.decodeHex(inHexBytes.replace(" ", "").toCharArray());
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);

		keccack1600.setXorBytes(0, inBytes, 0, inBytes.length);
		
		keccack1600.theta();
				
		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		return outBytes;
	}
	
	byte[] getPiBytes(byte[] inBytes) throws Exception
	{
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);

		keccack1600.setXorBytes(0, inBytes, 0, inBytes.length);
		
		keccack1600.pi();
				
		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		return outBytes;
	}
	
	byte[] getRhoBytes(byte[] inBytes) throws Exception
	{
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);

		keccack1600.setXorBytes(0, inBytes, 0, inBytes.length);
		
		keccack1600.rho();
				
		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		return outBytes;
	}
	
	byte[] getChiBytes(byte[] inBytes) throws Exception
	{
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);

		keccack1600.setXorBytes(0, inBytes, 0, inBytes.length);
		
		keccack1600.chi();
				
		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		return outBytes;
	}
	
	byte[] getIotaBytes(byte[] inBytes, int round) throws Exception
	{
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);

		keccack1600.setXorBytes(0, inBytes, 0, inBytes.length);
		
		keccack1600.iota(round);
				
		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		return outBytes;
	}
	
	
	
	@Test
	public void testTeta() throws Exception
	{
		String outHexBytes = hexWordsToHexBytes("AF463273CA4D877D AF9FDF84CEC209D0 28C573DB9CDDA7BA ABBCDA349E794C02 FD3CB094025A23B6  "+
				"A1F41927F522354E BBB4F6DD5944099E 71068FC9EC9E2022 BB993BF3EAE000D3 4687A426B0860F85 "+
				"B5391435A9BB8CAF 82ECF55BF0736F59 7CF829D3E1485B0B 5511ACC9F2BECD69 77E6D18B71ACA57E "+
				"5B86DE50AB75F4FB 4FF4ED8F71CB3EA8 9C6B255041436845 AED5C751BE290B84 FA2A161B7CC6C129 "+
				"CA6FC42824967C8E 330BEA595FC747BE EBA860E3DD836B96 635FD9ED8EC9A474 9CE501EA3CE551A8 ");

		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(outHexBytes.replace(" ", "").toCharArray());

		Assert.assertTrue(Arrays.equals(expectedBytes, getTetaBytes()));		
	}
	
	@Test
	public void testRho() throws Exception 
	{
		String outHexBytes = hexWordsToHexBytes("AF463273CA4D877D 5F3FBF099D8413A1 8A315CF6E73769EE 49E794C02ABBCDA3 A012D11DB7E9E584 "+
				"522354EA1F41927F 4099EBBB4F6DD594 41A3F27B2788089C 69DDCC9DF9F57000 426B0860F854687A "+	
				"A9C8A1AD4DDC657D B3D56FC1CDBD660B 42D85BE7C14E9F0A 93E57D9AD2AA2359 D652BF3BF368C5B8 "+
				"EBE9F6B70DBCA156 67D509FE9DB1EE39 92A820A1B422CE35 EA37C5217095DAB8 2A161B7CC6C129FA "+
				"10A09259F23B29BF CC2FA9657F1D1EF8 DD750C1C7BB06D72 74635FD9ED8EC9A4 407A8F39546A2739 "
		);
		
		
		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(outHexBytes.replace(" ", "").toCharArray());
		
		Assert.assertTrue(Arrays.equals(expectedBytes, getRhoBytes(getTetaBytes())));
	}
	
	
	@Test
	public void testPi() throws Exception
	{
		String outHexBytes = hexWordsToHexBytes("AF463273CA4D877D 4099EBBB4F6DD594 42D85BE7C14E9F0A EA37C5217095DAB8 407A8F39546A2739 "+
				"49E794C02ABBCDA3 426B0860F854687A A9C8A1AD4DDC657D 67D509FE9DB1EE39 DD750C1C7BB06D72 "+
				"5F3FBF099D8413A1 41A3F27B2788089C 93E57D9AD2AA2359 2A161B7CC6C129FA 10A09259F23B29BF "+
				"A012D11DB7E9E584 522354EA1F41927F B3D56FC1CDBD660B 92A820A1B422CE35 74635FD9ED8EC9A4 "+
				"8A315CF6E73769EE 69DDCC9DF9F57000 D652BF3BF368C5B8 EBE9F6B70DBCA156 CC2FA9657F1D1EF8 "
		);
		
		
		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(outHexBytes.replace(" ", "").toCharArray());
		
		Assert.assertTrue(Arrays.equals(expectedBytes, getPiBytes(getRhoBytes(getTetaBytes()))));		
	}
	
	@Test 
	public void testChi() throws Exception 
	{
		String outHexBytes = hexWordsToHexBytes("AD0622374A4F8D77 E8BE6FBB7FFC9524 429051FFC524BA0B 4533F563FA905AFC 00E346B1514A77B9 "+
		"E067354D2F33C8A6 047E00326875E27A 31E8A5AD2FDC643F 6757993E9DBA6EB8 DF7D043CABF44D2A "+
		"CD7BB2894DA630E0 69B1F01F23C9003E 8345FD9BE290235C 6509367CCB453BFA 1020D22BD03321A3 "+
		"01C6FA1C77558184 520B54CA2F431A4B D79630998431678B 12B8A0A5A643EA35 26425B3BE58EDBDF "+
		"1C336FD4E53FEC56 40748C19F5615046 D254B67B8169DB10 E9F9A2258D9EC050 ADE3296C67DD0EF8 ");
		
		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(outHexBytes.replace(" ", "").toCharArray());
		
		Assert.assertTrue(Arrays.equals(expectedBytes, getChiBytes(getPiBytes(getRhoBytes(getTetaBytes())))));				
	}
	
	@Test
	public void testIota() throws Exception 
	{
		String outHexBytes = hexWordsToHexBytes(
				"AD0622374A4F8D76 E8BE6FBB7FFC9524 429051FFC524BA0B 4533F563FA905AFC 00E346B1514A77B9 "+
				"E067354D2F33C8A6 047E00326875E27A 31E8A5AD2FDC643F 6757993E9DBA6EB8 DF7D043CABF44D2A "+
				"CD7BB2894DA630E0 69B1F01F23C9003E 8345FD9BE290235C 6509367CCB453BFA 1020D22BD03321A3 "+
				"01C6FA1C77558184 520B54CA2F431A4B D79630998431678B 12B8A0A5A643EA35 26425B3BE58EDBDF "+
				"1C336FD4E53FEC56 40748C19F5615046 D254B67B8169DB10 E9F9A2258D9EC050 ADE3296C67DD0EF8 "); 

		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(outHexBytes.replace(" ", "").toCharArray());
		
		Assert.assertTrue(Arrays.equals(expectedBytes, getIotaBytes(getChiBytes(getPiBytes(getRhoBytes(getTetaBytes()))),0)));						
	}

	@Test
	public void testPermuteZero() throws Exception
	{
		String expectedHexBytes
		 = "E7 DD E1 40 79 8F 25 F1 8A 47 C0 33 F9 CC D5 84 EE A9 5A A6 1E 26 98 D5 4D 49 80 6F 30 47 15 BD 57 D0 53 62 05 4E 28 8B D4 6F 8E 7F 2D A4 97 FF C4 47 46 A4 A0 E5 FE 90 76 2E 19 D6 0C DA 5B 8C 9C 05 19 1B F7 A6 30 AD 64 FC 8F D0 B7 5A 93 30 35 D6 17 23 3F A9 5A EB 03 21 71 0D 26 E6 A6 A9 5F 55 CF DB 16 7C A5 81 26 C8 47 03 CD 31 B8 43 9F 56 A5 11 1A 2F F2 01 61 AE D9 21 5A 63 E5 05 F2 70 C9 8C F2 FE BE 64 11 66 C4 7B 95 70 36 61 CB 0E D0 4F 55 5A 7C B8 C8 32 CF 1C 8A E8 3E 8C 14 26 3A AE 22 79 0C 94 E4 09 C5 A2 24 F9 41 18 C2 65 04 E7 26 35 F5 16 3B A1 30 7F E9 44 F6 75 49 A2 EC 5C 7B FF F1 EA";
		
		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(expectedHexBytes.replace(" ", "").toCharArray());
				
		byte[] outBytes = new byte[1600/8];

		Keccack1600 keccack1600 = new Keccack1600(0);
		keccack1600.permute();

		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		
		Assert.assertTrue(Arrays.equals(expectedBytes, outBytes));		
	}
	
	@Test
	public void testPermuteNonZero() throws Exception
	{
		String expectedtHexBytes = 
			"3C CB 6E F9 4D 95 5C 2D 6D B5 57 70 D0 2C 33 6A 6C 6B D7 70 12 8D 3D 09 94 D0 69 55 B2 D9 20 8A 56 F1 E7 E5 99 4F 9C 4F 38 FB 65 DA A2 B9 57 F9 0D AF 75 12 AE 3D 77 85 F7 10 D8 C3 47 F2 F4 FA 59 87 9A F7 E6 9E 1B 1F 25 B4 98 EE 0F CC FE E4 A1 68 CE B9 B6 61 CE 68 4F 97 8F BA C4 66 EA DE F5 B1 AF 6E 83 3D C4 33 D9 DB 19 27 04 54 06 E0 65 12 83 09 F0 A9 F8 7C 43 47 17 BF A6 49 54 FD 40 4B 99 D8 33 AD DD 97 74 E7 0B 5D FC D5 EA 48 3C B0 B7 55 EE C8 B8 E3 E9 42 9E 64 6E 22 A0 91 7B DD BA E7 29 31 0E 90 E8 CC A3 FA C5 9E 2A 20 B6 3D 1C 4E 46 02 34 5B 59 10 4C A4 62 4E 9F 60 5C BF 8F 6A D2 6C D0 20";
		
		byte[] expectedBytes = org.apache.commons.codec.binary.Hex.decodeHex(expectedtHexBytes .replace(" ", "").toCharArray());
		byte[] outBytes = new byte[1600/8];
		
		Keccack1600 keccack1600 = new Keccack1600(0);
		keccack1600.permute();
		keccack1600.permute();

		keccack1600.getBytes(0, outBytes, 0, outBytes.length);
		Assert.assertTrue(Arrays.equals(expectedBytes, outBytes));			
	}
	
	@Test
	public void testPermutationSpeed() {
		int ROUNDS=15;
		int BENCH=100000;

		Keccack1600 keccack1600 = new Keccack1600(0);
		long total=0;
		for(int i=0; i < ROUNDS; ++i) {
			long ts1 = System.currentTimeMillis();
			for(int j=0; j < BENCH; ++j) {
				keccack1600.permute();
			}
			long ts2 = System.currentTimeMillis();
			total += (ts2-ts1);
		}
		System.out.println("Average Permutation speed: "+ ROUNDS*BENCH*1000/(total) + " permutations/second. ");
	}
	
		
}
