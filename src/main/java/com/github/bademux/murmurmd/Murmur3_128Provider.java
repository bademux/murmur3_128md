package com.github.bademux.murmurmd;

import static com.github.bademux.murmurmd.Murmur3_128MessageDigest.DESCRIPTION;
import static com.github.bademux.murmurmd.Murmur3_128MessageDigest.NAME;
import static com.github.bademux.murmurmd.Murmur3_128MessageDigest.VERSION;

import java.security.Provider;

public class Murmur3_128Provider extends Provider {
	public Murmur3_128Provider() {
		super(NAME, VERSION, DESCRIPTION);
		put("MessageDigest." + NAME, Murmur3_128MessageDigest.class.getName());
	}
}