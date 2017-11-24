package com.github.aelstad.keccakj.keyak.v2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;

import com.github.aelstad.keccakj.keyak.v2.LakeKeyak;

public class TestLakeKeyak {

	byte[] tagBuf = new byte[16];

	byte[] generateSimpleRawMaterial(int len, int seed1, int seed2)
	{
		seed1 &= 0xff;
		byte[] rv = new byte[len];
		for(int i=0; i < len; ++i) {
			int iRolled= ((i&0xff) << (seed2&7)) | ((i&0xff) >>> 8-(seed2&7));
			int val = seed1 + (161*len) - iRolled + i;
			val &= 0xff;
			rv[i] = (byte) val;
		}
		return rv;
	}

	String getHexString(byte[] rv) {
		String tmp = Hex.encodeHexString(rv);
		String formatted="";
		for(int i=0; i < tmp.length(); i+=2) {
			if(formatted.length()>0) formatted += " ";
			formatted += tmp.substring(i, i+2);
		}
		return formatted;
	}

	void startEngine(LakeKeyak global, LakeKeyak wrap, LakeKeyak unwrap, byte[] key, byte[] nonce, boolean tag, boolean forget) throws IOException, InvalidKeyException {
		System.out.println("*** LakeKeyak");
		System.out.println("StartEngine(K,N,tagFlag="+tag+",forget="+forget+")");
		System.out.println(String.format(">K: %s", getHexString(key)));
		System.out.println(String.format(">N: %s", getHexString(nonce)));
		byte[] tagWrap = tag ? new byte[16] : null;
		wrap.init(key, nonce, 0, nonce.length, tagWrap, 0, forget, false);
		unwrap.init(key, nonce, 0, nonce.length, tagWrap, 0, forget, true);
		if(tag) {
			System.out.println(String.format("< T (tag) %s", getHexString(tagWrap)));
			global.wrap(null, new ByteArrayInputStream(tagWrap), null, tagWrap, 0, false);
		}
		System.out.println();
	}

	void wrapUnwrap(LakeKeyak global, LakeKeyak wrap, LakeKeyak unwrap, byte[] acontent, byte[] pcontent, boolean forget) throws IOException
	{
		System.out.println("Wrap(I, O, A, T, unwrapFlag=false, forgetFlag="+forget+"), with:");
		System.out.println(String.format("> A (metadata) %s", getHexString(acontent)));
		System.out.println(String.format("> I (plaintext) %s", getHexString(pcontent)));
		ByteArrayOutputStream bos  = new ByteArrayOutputStream();
		byte[] tag = new byte[16];
		wrap.wrap(new ByteArrayInputStream(pcontent), new ByteArrayInputStream(acontent), bos, tag, 0, forget);

		System.out.println(String.format("< O (ciphertext) %s", getHexString(bos.toByteArray())));
		System.out.println(String.format("< T (tag) %s", getHexString(tag)));
		global.wrap(null, new ByteArrayInputStream(bos.toByteArray()), null, tagBuf, 0, false);
		global.wrap(null, new ByteArrayInputStream(tag), null, tagBuf, 0, false);
		ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
		unwrap.unwrap(new ByteArrayInputStream(bos.toByteArray()), new ByteArrayInputStream(acontent), plaintext, tag, 0, forget);

		Assert.assertArrayEquals(plaintext.toByteArray(), pcontent);
		System.out.println();
	}

	public byte[] test(boolean oneBlockSuv) throws IOException, InvalidKeyException {
		LakeKeyak global = new LakeKeyak();
		global.init(new byte[0], null, 0, 0, null, 0, false, false);

		byte[] ABC = new byte[] { 'A','B','C'};
		byte[] DEF = new byte[] { 'D','E','F'};

		int ra = 192;
		int rs = 168;

		int nlenMax = oneBlockSuv ? 150 : 200;

		for(int keylen = 16; keylen <= 32; keylen++) {
			for(int nlen = 0; nlen <= nlenMax; nlen += (keylen == 16) ? 1 : nlenMax) {
				for(int forgetFlag = 0; forgetFlag < 2; ++forgetFlag) {
					for(int tagFlag = 0; tagFlag < 2; ++tagFlag) {
						LakeKeyak wrap = new LakeKeyak();
						LakeKeyak unwrap = new LakeKeyak();

						startEngine(global, wrap, unwrap, generateSimpleRawMaterial(keylen, keylen+nlen+0x12, 3),
								generateSimpleRawMaterial(nlen, keylen+nlen+0x45, 6), tagFlag != 0, forgetFlag != 0);

						wrapUnwrap(global, wrap, unwrap, ABC, DEF, false);
					}
				}
			}
		}

		List<Integer> alengths = new ArrayList<Integer>();
		alengths.add(0);
		alengths.add(1);
		alengths.add((ra-rs)-1);
		alengths.add((ra-rs));
		alengths.add((ra-rs)+1);

		for(int forgetFlag=0; forgetFlag < 2; ++forgetFlag) {
			for(int tagFlag = 0; tagFlag < 2; ++tagFlag) {
				for(int aidx = 0; aidx < alengths.size(); ++aidx) {
					for(int mlen=0; mlen <= rs+1; mlen += (aidx==0) ? 1 : (1+forgetFlag)*(8+tagFlag)+1) {
						int klen = 16;
						int nlen = 150;
						int alen = alengths.get(aidx);

						LakeKeyak wrap = new LakeKeyak();
						LakeKeyak unwrap = new LakeKeyak();

						startEngine(global, wrap, unwrap,
								generateSimpleRawMaterial(klen, 0x23+mlen+alen, 4),
								generateSimpleRawMaterial(nlen, 0x56+mlen+alen, 7),
								tagFlag!=0, forgetFlag!=0);

						wrapUnwrap(global, wrap, unwrap, generateSimpleRawMaterial(alen, 0xAB+mlen+alen, 3),
								generateSimpleRawMaterial(mlen, 0xcd+mlen+alen, 4), forgetFlag!=0);

						wrapUnwrap(global, wrap, unwrap, generateSimpleRawMaterial(alen, 0xCD+mlen+alen, 3),
								generateSimpleRawMaterial(mlen, 0xEF+mlen+alen, 4), forgetFlag!=0);

					}
				}
			}
		}

		List<Integer> mlengths = new ArrayList<Integer>();
		mlengths.add(0);
		mlengths.add(1);
		mlengths.add(rs-1);
		mlengths.add(rs);
		mlengths.add(rs+1);

		for(int forgetFlag=0; forgetFlag < 2; ++forgetFlag) {
			for(int tagFlag = 0; tagFlag < 2; ++tagFlag) {
				for(int midx = 0; midx < mlengths.size(); ++midx) {
					for(int alen=0; alen <= ra+1; alen += (midx==0) ? 1 : (1+forgetFlag)*(8+tagFlag)+1) {
						int klen = 16;
						int nlen = 150;
						int mlen = mlengths.get(midx);

						LakeKeyak wrap = new LakeKeyak();
						LakeKeyak unwrap = new LakeKeyak();

						startEngine(global, wrap, unwrap,
								generateSimpleRawMaterial(klen, 0x34+mlen+alen, 5),
								generateSimpleRawMaterial(nlen, 0x45+mlen+alen, 6),
								tagFlag!=0, forgetFlag!=0);

						wrapUnwrap(global, wrap, unwrap, generateSimpleRawMaterial(alen, 0x01+mlen+alen, 5),
								generateSimpleRawMaterial(mlen, 0x23+mlen+alen, 6), forgetFlag!=0);

						wrapUnwrap(global, wrap, unwrap, generateSimpleRawMaterial(alen, 0x45+mlen+alen, 5),
								generateSimpleRawMaterial(mlen, 0x67+mlen+alen, 6), forgetFlag!=0);

					}
				}
			}
		}

		for(int forgetFlag=0; forgetFlag < 2; ++forgetFlag) {
			for(int tagFlag=0; tagFlag < 2; ++tagFlag) {
				int klen=16;
				int nlen=150;

				LakeKeyak wrap = new LakeKeyak();
				LakeKeyak unwrap = new LakeKeyak();

				startEngine(global, wrap, unwrap,
						generateSimpleRawMaterial(klen, forgetFlag*2+tagFlag, 1),
						generateSimpleRawMaterial(nlen, forgetFlag*2+tagFlag, 2),
						tagFlag!=0, forgetFlag!=0);

				for(int alen=0; alen <= ra*2; alen += alen/3+1) {
					for(int mlen=0; mlen <= rs*2; mlen += mlen/2 + 1 + alen) {
						wrapUnwrap(global, wrap, unwrap, generateSimpleRawMaterial(alen, 0x34+mlen+alen, 3),
								generateSimpleRawMaterial(mlen, 0x45+mlen+alen, 4), forgetFlag!=0);
					}
				}

			}
		}

		byte[] rv = new byte[16];
		global.wrap(null, null, null, rv, 0, false);
		return rv;
	}

	@Test
	public void testOneBlockSuv() throws InvalidKeyException, IOException, DecoderException {
		byte[] expected = Hex.decodeHex("7303c4ba1effc39d488065c2fd05f752".toCharArray());
		byte[] tag = test(true);
		Assert.assertArrayEquals(expected, tag);
	}

	@Test
	public void testLongSuv() throws InvalidKeyException, IOException, DecoderException {
		byte[] expected = Hex.decodeHex("8395c64122bb430432d8b0298209b736".toCharArray());
		byte[] tag = test(false);
		Assert.assertArrayEquals(expected, tag);
	}
}
