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

package com.nimbusds.jose.util;


import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;


public class KeyUtilsTest extends TestCase {
	
	
	public void testToAESSecretKey()
		throws Exception {
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey key = gen.generateKey();
		
		assertEquals(128, ByteUtils.bitLength(key.getEncoded()));
		assertEquals("AES", key.getAlgorithm());
		
		key = new SecretKeySpec(key.getEncoded(), "UNKNOWN");
		assertEquals(128, ByteUtils.bitLength(key.getEncoded()));
		assertEquals("UNKNOWN", key.getAlgorithm());
		
		SecretKey aesKey = KeyUtils.toAESKey(key);
		assertEquals(128, ByteUtils.bitLength(key.getEncoded()));
		assertTrue(Arrays.equals(key.getEncoded(), aesKey.getEncoded()));
		assertEquals("AES", aesKey.getAlgorithm());
	}
	
	
	public void testToAESSecretKey_null() {
		
		assertNull(KeyUtils.toAESKey(null));
	}
}
