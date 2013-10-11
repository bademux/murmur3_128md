package com.github.bademux.murmurmd;

import static com.github.bademux.murmurmd.Murmur3_128MessageDigest.NAME;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.github.bademux.murmurmd.Murmur3_128Provider;

public class Murmur3Hash128Test {

	private static MessageDigest md;

	@Before
	public void init() throws NoSuchAlgorithmException {
		Security.addProvider(new Murmur3_128Provider());
		md = MessageDigest.getInstance(NAME);
		assertEquals(128 / Byte.SIZE, md.getDigestLength());
	}

	@After
	public void cleanup() {
		md.reset();
	}

	@Test
	public void testKnownValues() {
		assertHash(toBytes(0x629942693e10f867L, 0x92db0b82baeb5347L),
				"hell".getBytes());
		assertHash(toBytes(0xe34bbc7bbc071b6cL, 0x7a433ca9c49a9347L),
				"The quick brown fox jumps over the lazy dog".getBytes());
		assertHash(toBytes(0x658ca970ff85269aL, 0x43fee3eaa68e5c3eL),
				"The quick brown fox jumps over the lazy cog".getBytes());
	}

	@Test
	public void testKnownValuesChunk() {
		assertHashByChunk(toBytes(0x629942693e10f867L, 0x92db0b82baeb5347L),
				"hell".getBytes(), 1);
		assertHashByChunk(toBytes(0xe34bbc7bbc071b6cL, 0x7a433ca9c49a9347L),
				"The quick brown fox jumps over the lazy dog".getBytes(), 1);
		assertHashByChunk(toBytes(0x658ca970ff85269aL, 0x43fee3eaa68e5c3eL),
				"The quick brown fox jumps over the lazy cog".getBytes(), 16);
	}

	private static void assertHash(byte[] expectedHash, byte[] input) {
		md.update(input);
		assertArrayEquals(expectedHash, md.digest());
	}

	private static void assertHashByChunk(byte[] expectedHash, byte[] input,
			int chunk) {
		for (int i = 0; i < input.length; i += chunk) {
			int len = chunk > input.length - i ? input.length - i : chunk;
			md.update(input, i, len);
		}

		assertArrayEquals(expectedHash, md.digest());
	}

	private static byte[] toBytes(long... longs) {
		ByteBuffer bb = ByteBuffer.allocate(longs.length * Byte.SIZE).order(
				ByteOrder.LITTLE_ENDIAN);
		for (long x : longs) {
			bb.putLong(x);
		}
		return bb.array();
	}

	public static String bytes2hex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(2 * bytes.length);
		for (byte b : bytes) {
			sb.append(hexDigits[(b >> 4) & 0xf]).append(hexDigits[b & 0xf]);
		}
		return sb.toString();
	}

	private static final char[] hexDigits = "0123456789abcdef".toCharArray();
}
