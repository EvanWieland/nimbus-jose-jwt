package com.nimbusds.jose.proc;

import java.security.Key;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

/**
 * A {@link JWSKeySelector} that always returns the same {@link Key}.
 */
public class SingleKeyJWSKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {
	private final List<Key> keySet;
	private final JWSAlgorithm expectedJwsAlgorithm;

	/**
	 * Creates a new single-key jws key selector
	 *
	 * @param expectedJwsAlgorithm The expected JWS algorithm for the objects to be
	 *                             verified. Must not be {@code null}.
	 * @param key                  The key to always return
	 */
	public SingleKeyJWSKeySelector(JWSAlgorithm expectedJwsAlgorithm, Key key) {
		if (expectedJwsAlgorithm == null) {
			throw new IllegalArgumentException("expectedJwsAlgorithm cannot be null");
		}
		if (key == null) {
			throw new IllegalArgumentException("key cannot be null");
		}
		this.keySet = Arrays.asList(key);
		this.expectedJwsAlgorithm = expectedJwsAlgorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<? extends Key> selectJWSKeys(JWSHeader header, C context) {
		if (!this.expectedJwsAlgorithm.equals(header.getAlgorithm())) {
			throw new IllegalArgumentException("Unsupported algorithm of " + header.getAlgorithm());
		}
		return this.keySet;
	}
}
