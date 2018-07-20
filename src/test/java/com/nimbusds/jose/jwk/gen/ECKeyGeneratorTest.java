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
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


public class ECKeyGeneratorTest extends TestCase {
	
	
	public void testGenMinimal()
		throws JOSEException  {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.generate();
		
		assertEquals(Curve.P_256, ecJWK.getCurve());
		
		assertNull(ecJWK.getKeyUse());
		assertNull(ecJWK.getKeyOperations());
		assertNull(ecJWK.getAlgorithm());
		assertNull(ecJWK.getKeyID());
		assertNull(ecJWK.getKeyStore());
	}


	// The x, y, d values that are generated should all be distinct
	public void testDistinctness()
		throws JOSEException  {

		Set<Base64URL> values = new HashSet<>();

		ECKeyGenerator gen = new ECKeyGenerator(Curve.P_256);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}

		gen = new ECKeyGenerator(Curve.P_384);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}

		gen = new ECKeyGenerator(Curve.P_521);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}
	}
	
	
	public void testGenWithParams_explicitKeyID()
		throws JOSEException  {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.ES256)
			.keyID("1")
			.generate();
		
		assertEquals(Curve.P_256, ecJWK.getCurve());
		
		assertEquals(KeyUse.SIGNATURE, ecJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), ecJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, ecJWK.getAlgorithm());
		assertEquals("1", ecJWK.getKeyID());
		assertNull(ecJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException  {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.ES256)
			.keyIDFromThumbprint(true)
			.generate();
		
		assertEquals(Curve.P_256, ecJWK.getCurve());
		
		assertEquals(KeyUse.SIGNATURE, ecJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), ecJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, ecJWK.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(ecJWK).toString(), ecJWK.getKeyID());
		assertNull(ecJWK.getKeyStore());
	}


	// Ed25519 and X25519 are not allowed in EC keys.
	// See OctetKeyPair instead.
	public void testGenInvalidCurves()
		throws JOSEException  {

		try {
			ECKey ecJWK = new ECKeyGenerator(Curve.Ed25519).generate();
			fail();

		} catch (Exception e) {
			// Passed
		}

		try {
			ECKey ecJWK = new ECKeyGenerator(Curve.X25519).generate();
			fail();

		} catch (Exception e) {
			// Passed
		}
	}
}
