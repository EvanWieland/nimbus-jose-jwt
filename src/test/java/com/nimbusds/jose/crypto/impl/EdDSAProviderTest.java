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
import com.nimbusds.jose.crypto.impl.EdDSAProvider;
import junit.framework.TestCase;


/**
 * @author Tim McLean
 * @version 2018-07-12
 */
public class EdDSAProviderTest extends TestCase {


	public void testSupportedAlgorithms() {

		assertTrue(EdDSAProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.EdDSA));
		assertEquals(1, EdDSAProvider.SUPPORTED_ALGORITHMS.size());
	}
}
