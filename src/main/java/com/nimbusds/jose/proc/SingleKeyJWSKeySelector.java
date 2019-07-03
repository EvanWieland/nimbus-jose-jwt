package com.nimbusds.jose.proc;


import java.security.Key;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;


/**
 * A {@link JWSKeySelector} that always returns the same {@link Key}.
 *
 * @author Josh Cummings
 */
public class SingleKeyJWSKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {
	
	
	private final List<Key> singletonKeyList;
	
	private final JWSAlgorithm expectedJWSAlg;
	

	/**
	 * Creates a new single-key JWS key selector.
	 *
	 * @param expectedJWSAlg The expected JWS algorithm for the JWS
	 *                       objects to be verified. Must not be
	 *                       {@code null}.
	 * @param key            The key to always return. Must not be
	 *                       {@code null}.
	 */
	public SingleKeyJWSKeySelector(final JWSAlgorithm expectedJWSAlg, final Key key) {
		if (expectedJWSAlg == null) {
			throw new IllegalArgumentException("The expected JWS algorithm cannot be null");
		}
		if (key == null) {
			throw new IllegalArgumentException("The key cannot be null");
		}
		this.singletonKeyList = Collections.singletonList(key);
		this.expectedJWSAlg = expectedJWSAlg;
	}

	
	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final C context) {
		
		if (! this.expectedJWSAlg.equals(header.getAlgorithm())) {
			return Collections.emptyList();
		}
		
		return this.singletonKeyList;
	}
}
