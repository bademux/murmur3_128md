package com.github.bademux.murmurmd;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigestSpi;

/**
 * GWT implementation of Murmur 3 128bit little endian.
 */
public final class Murmur3_128MessageDigest extends MessageDigestSpi {

	public static final String NAME = "Murmur3_128";
	public static final String DESCRIPTION = "GWT implementation of Murmur 3 128bit little endian";
	public static final double VERSION = 0.1;

	private final static long C1 = 0x87c37b91114253d5L;
	private final static long C2 = 0x4cf5ad432745937fL;

	private final static int DIGEST_LENGTH = (Long.SIZE * 2) / Byte.SIZE;

	private final ByteBuffer tmpBuffer = ByteBuffer.allocate(DIGEST_LENGTH)
			.order(ByteOrder.LITTLE_ENDIAN);

	private long length = 0L;
	private int seed = 0; // unused
	private long h1;
	private long h2;

	public Murmur3_128MessageDigest(int seed) {
		this();
		this.seed = seed;

	}

	public Murmur3_128MessageDigest() {
		engineReset();
	}

	@Override
	protected byte[] engineDigest() {
		// if tmpBuffer isn't empty
		if (tmpBuffer.position() != 0) {
			length += tmpBuffer.position();
			tmpBuffer.flip();
			processRemainingInput(tmpBuffer);
		}

		h1 ^= length;
		h2 ^= length;

		h1 += h2;
		h2 += h1;

		h1 = fmix(h1);
		h2 = fmix(h2);

		h1 += h2;
		h2 += h1;

		byte[] hash = ByteBuffer.allocate(DIGEST_LENGTH)
				.order(ByteOrder.LITTLE_ENDIAN).putLong(h1).putLong(h2).array();
		engineReset();
		return hash;
	}

	@Override
	protected int engineGetDigestLength() {
		return DIGEST_LENGTH;
	}

	@Override
	protected void engineReset() {
		tmpBuffer.clear();
		length = 0L;
		h1 = seed;
		h2 = seed;
	}

	@Override
	protected void engineUpdate(byte input) {
		engineUpdate(new byte[] { input }, 0, 1);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		engineUpdate(ByteBuffer.wrap(input, offset, len));
	}

	@Override
	protected void engineUpdate(ByteBuffer aInput) {
		ByteBuffer input = aInput.asReadOnlyBuffer().order(
				ByteOrder.LITTLE_ENDIAN);

		int numOfChunks = (tmpBuffer.position() + input.remaining())
				/ DIGEST_LENGTH;

		// combine tmpBuff and input buff
		if (numOfChunks > 0) {
			processBuffer(processFullChunks(input, numOfChunks));
		}

		// if sum tmpBuffer + inputBuff isn't match
		// save unused bytes to buffer
		if (input.remaining() > 0) {
			tmpBuffer.put(input);
		}
	}

	/**
	 * Prepare unused bytes in input buffer do be saved for further processing
	 * with tmpBuff
	 * 
	 * @param input
	 * @param numOfChunks
	 *            - number of full chunks
	 * @return buffer with full chunks
	 */
	private ByteBuffer processFullChunks(final ByteBuffer input, int numOfChunks) {
		int fullChunkLength = numOfChunks * DIGEST_LENGTH;
		// if tmpBuffer is empty
		if (tmpBuffer.position() == 0) {
			// if tmpBuffer is empty and inputBuff matched
			if ((input.limit() % DIGEST_LENGTH) == 0) {
				return input;
			}
			// make length fits to mixBody()
			ByteBuffer buff = input.asReadOnlyBuffer().order(
					ByteOrder.LITTLE_ENDIAN);
			buff.limit(fullChunkLength);

			// get unmatched "tail"
			input.position(fullChunkLength);
			return buff;
		}

		if ((tmpBuffer.position() + input.remaining()) == DIGEST_LENGTH) {
			// if fits to tmp butter
			tmpBuffer.put(input);
			tmpBuffer.clear();
			return tmpBuffer.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN);
		}

		// leave unused bytes for further tmpBuffer operation
		ByteBuffer buff = ByteBuffer.allocate(fullChunkLength).order(
				ByteOrder.LITTLE_ENDIAN);
		// respect input buff limit
		int oldLimit = input.limit();
		input.limit(fullChunkLength - tmpBuffer.position());
		// put bytes from tmp buff first
		if (tmpBuffer.position() > 0) {
			tmpBuffer.flip();
			buff.put(tmpBuffer);
			tmpBuffer.clear();
		}

		buff.put(input);

		input.limit(oldLimit);
		return buff;
	}

	private void processBuffer(ByteBuffer byteBuff) {
		length += byteBuff.remaining();
		while (byteBuff.hasRemaining()) {
			mixBody(byteBuff.getLong(), byteBuff.getLong());
		}
	}

	protected void processRemainingInput(ByteBuffer bb) {
		long k1 = 0;
		long k2 = 0;

		switch (bb.remaining()) {
		case 15:
			k2 ^= (bb.get(14) & 0xFFL) << 48; // fall through
		case 14:
			k2 ^= (bb.get(13) & 0xFFL) << 40; // fall through
		case 13:
			k2 ^= (bb.get(12) & 0xFFL) << 32; // fall through
		case 12:
			k2 ^= (bb.get(11) & 0xFFL) << 24; // fall through
		case 11:
			k2 ^= (bb.get(10) & 0xFFL) << 16; // fall through
		case 10:
			k2 ^= (bb.get(9) & 0xFFL) << 8; // fall through
		case 9:
			k2 ^= (bb.get(8)); // fall through
		case 8:
			k1 ^= bb.getLong();
			break;
		case 7:
			k1 ^= (bb.get(6) & 0xFFL) << 48; // fall through
		case 6:
			k1 ^= (bb.get(5) & 0xFFL) << 40; // fall through
		case 5:
			k1 ^= (bb.get(4) & 0xFFL) << 32; // fall through
		case 4:
			k1 ^= (bb.get(3) & 0xFFL) << 24; // fall through
		case 3:
			k1 ^= (bb.get(2) & 0xFFL) << 16; // fall through
		case 2:
			k1 ^= (bb.get(1) & 0xFFL) << 8; // fall through
		case 1:
			k1 ^= (bb.get(0));
			break;
		default:
			throw new AssertionError("Should never get here.");
		}
		h1 ^= mixK1(k1);
		h2 ^= mixK2(k2);
	}

	private void mixBody(long k1, long k2) {
		h1 ^= mixK1(k1);

		h1 = Long.rotateLeft(h1, 27);
		h1 += h2;
		h1 = h1 * 5 + 0x52dce729;

		h2 ^= mixK2(k2);

		h2 = Long.rotateLeft(h2, 31);
		h2 += h1;
		h2 = h2 * 5 + 0x38495ab5;
	}

	private long mixK1(long k1) {
		k1 *= C1;
		k1 = Long.rotateLeft(k1, 31);
		k1 *= C2;
		return k1;
	}

	private long mixK2(long k2) {
		k2 *= C2;
		k2 = Long.rotateLeft(k2, 33);
		k2 *= C1;
		return k2;
	}

	private long fmix(long k) {
		// avalanche bits
		k ^= k >>> 33;
		k *= 0xff51afd7ed558ccdL;
		k ^= k >>> 33;
		k *= 0xc4ceb9fe1a85ec53L;
		k ^= k >>> 33;
		return k;
	}
}
