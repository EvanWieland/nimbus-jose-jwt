/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk.gen;


import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ThumbprintUtils;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


public class RSAKeyGeneratorTest extends TestCase {
	
	
	public void testMinKeySize() {
		
		assertEquals(2048, RSAKeyGenerator.MIN_KEY_SIZE_BITS);
		
		try {
			new RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS - 1);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The key size must be at least 2048 bits", e.getMessage());
		}
	}
	
	
	public void testAllowWeakKeys()
		throws JOSEException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(1024, true).generate();
		
		assertEquals(1024, rsaJWK.size());
	}
	
	
	public void testGenMinimal()
		throws JOSEException  {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.generate();
		
		assertEquals(2048, rsaJWK.size());
		
		assertNull(rsaJWK.getKeyUse());
		assertNull(rsaJWK.getKeyOperations());
		assertNull(rsaJWK.getAlgorithm());
		assertNull(rsaJWK.getKeyID());
		assertNull(rsaJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_explicitKeyID()
		throws JOSEException  {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.generate();
		
		assertEquals(2048, rsaJWK.size());
		
		assertEquals(KeyUse.SIGNATURE, rsaJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), rsaJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, rsaJWK.getAlgorithm());
		assertEquals("1", rsaJWK.getKeyID());
		assertNull(rsaJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException  {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.RS256)
			.keyIDFromThumbprint(true)
			.generate();
		
		assertEquals(2048, rsaJWK.size());
		
		assertEquals(KeyUse.SIGNATURE, rsaJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), rsaJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, rsaJWK.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(rsaJWK).toString(), rsaJWK.getKeyID());
		assertNull(rsaJWK.getKeyStore());
	}


	// The n, d, p, q, dp, dq, qi values that are generated should all be distinct
	public void testDistinctness()
		throws JOSEException  {

		Set<Base64URL> values = new HashSet<>();

		RSAKeyGenerator gen = new RSAKeyGenerator(2048);

		for (int i=0; i<3; i++) {

			RSAKey k = gen.generate();
			assertTrue(values.add(k.getModulus()));
			assertTrue(values.add(k.getPrivateExponent()));
			assertTrue(values.add(k.getFirstPrimeFactor()));
			assertTrue(values.add(k.getSecondPrimeFactor()));
			assertTrue(values.add(k.getFirstFactorCRTExponent()));
			assertTrue(values.add(k.getSecondFactorCRTExponent()));
			assertTrue(values.add(k.getFirstCRTCoefficient()));
		}
	}
}
