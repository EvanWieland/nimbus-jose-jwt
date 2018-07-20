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
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.ThumbprintUtils;
import junit.framework.TestCase;


public class OctetSequenceKeyGeneratorTest extends TestCase {
	
	
	public void testGenMinimal()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertNull(octJWK.getKeyUse());
		assertNull(octJWK.getKeyOperations());
		assertNull(octJWK.getAlgorithm());
		assertNull(octJWK.getKeyID());
		assertNull(octJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_explicitKeyID()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
			.algorithm(JWEAlgorithm.DIR)
			.keyID("1")
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertEquals(KeyUse.ENCRYPTION, octJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.ENCRYPT), octJWK.getKeyOperations());
		assertEquals(JWEAlgorithm.DIR, octJWK.getAlgorithm());
		assertEquals("1", octJWK.getKeyID());
		assertNull(octJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
			.algorithm(JWEAlgorithm.DIR)
			.keyIDFromThumbprint(true)
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertEquals(KeyUse.ENCRYPTION, octJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.ENCRYPT), octJWK.getKeyOperations());
		assertEquals(JWEAlgorithm.DIR, octJWK.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(octJWK).toString(), octJWK.getKeyID());
		assertNull(octJWK.getKeyStore());
	}
}
