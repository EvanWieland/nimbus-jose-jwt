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
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ThumbprintUtils;
import junit.framework.TestCase;


public class RSAKeyGeneratorTest extends TestCase {
	
	
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
}
