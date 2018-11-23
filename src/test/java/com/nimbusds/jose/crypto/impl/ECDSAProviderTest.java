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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSAProvider;
import junit.framework.TestCase;


/**
 * @author Vladimir Dzhuvinov
 * @version 2018-03-28
 */
public class ECDSAProviderTest extends TestCase {
	
	
	public void testSupportedAlgorithms() {
		
		assertTrue(ECDSAProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ES256));
		assertTrue(ECDSAProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ES256K));
		assertTrue(ECDSAProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ES384));
		assertTrue(ECDSAProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.ES512));
		assertEquals(4, ECDSAProvider.SUPPORTED_ALGORITHMS.size());
	}
}
