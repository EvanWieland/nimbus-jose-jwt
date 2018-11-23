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


import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import junit.framework.TestCase;
import org.junit.Assert;


public class RSAKeyUtilsTest extends TestCase {
	
	
	public void testConversion_ok() throws JOSEException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
		
		RSAPrivateKey privateKey = (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey(rsaJWK);
		
		assertEquals(2048, privateKey.getModulus().bitLength());
		
		Assert.assertArrayEquals(privateKey.getEncoded(), rsaJWK.toRSAPrivateKey().getEncoded());
	}
	
	
	public void testConversion_missing() throws JOSEException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate().toPublicJWK();
		
		try {
			RSAKeyUtils.toRSAPrivateKey(rsaJWK);
			fail();
		} catch (JOSEException e) {
			assertEquals("The RSA JWK doesn't contain a private part", e.getMessage());
		}
	}
	
	
	public void testKeyLength_known() throws JOSEException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
		
		assertEquals(2048, RSAKeyUtils.keyBitLength(rsaJWK.toPrivateKey()));
	}
	
	
	// PKCS#11
	public void testKeyLength_notKnown_privateKeyNotRSAPrivateKeyInstance() {
		
		PrivateKey privateKey = new PrivateKey() {
			@Override
			public String getAlgorithm() {
				return "RSA";
			}
			
			
			@Override
			public String getFormat() {
				return null;
			}
			
			
			@Override
			public byte[] getEncoded() {
				return new byte[0];
			}
		};
		
		assertEquals(-1, RSAKeyUtils.keyBitLength(privateKey));
	}
	
	
	// PKCS#11
	public void testKeyLength_notKnown_rsaPrivateKey_getModulusThrowsException() {
		
		PrivateKey rsaPrivateKey = new RSAPrivateKey() {
			@Override
			public BigInteger getPrivateExponent() {
				return null;
			}
			
			
			@Override
			public String getAlgorithm() {
				return "RSA";
			}
			
			
			@Override
			public String getFormat() {
				return null;
			}
			
			
			@Override
			public byte[] getEncoded() {
				return new byte[0];
			}
			
			
			@Override
			public BigInteger getModulus() {
				throw new RuntimeException("Operation not supported");
			}
		};
		
		assertEquals(-1, RSAKeyUtils.keyBitLength(rsaPrivateKey));
	}
}
