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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
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
}
