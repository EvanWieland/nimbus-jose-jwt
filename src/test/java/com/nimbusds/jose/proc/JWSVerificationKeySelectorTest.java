/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;
import org.junit.Assert;


public class JWSVerificationKeySelectorTest extends TestCase {
	

	public void testForRS256()
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Key rsa1 = keyPair.getPublic();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(rsa1.getEncoded());
		Base64URL thumbprint = Base64URL.encode(md.digest());

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) rsa1)
			.keyID("1")
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.x509CertSHA256Thumbprint(thumbprint)
			.build();

		keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.keyID("2")
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.build();

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
			JWSAlgorithm.RS256,
			new ImmutableJWKSet(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2))));

		assertEquals(JWSAlgorithm.RS256, keySelector.getExpectedJWSAlgorithm());
		assertNotNull(keySelector.getJWKSource());

		// Test JWK matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build());
		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("1"));
		assertTrue(m.getKeyUses().contains(KeyUse.SIGNATURE));
		assertTrue(m.getAlgorithms().contains(JWSAlgorithm.RS256));

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("2").build());
		assertNull(m);

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.HS256).build());
		assertNull(m);

		// Select for good header with key ID
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(), null);

		assertEquals(rsaJWK1.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(0)).getModulus());
		assertEquals(rsaJWK1.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(0)).getPublicExponent());

		assertEquals(1, candidates.size());

		// Select for good header without key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), null);

		assertEquals(rsaJWK1.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(0)).getModulus());
		assertEquals(rsaJWK1.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(0)).getPublicExponent());

		assertEquals(rsaJWK2.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(1)).getModulus());
		assertEquals(rsaJWK2.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(1)).getPublicExponent());

		assertEquals(2, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("100").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWS alg
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with SHA-256 Thumbprint
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertSHA256Thumbprint(thumbprint).build(), null);
		assertEquals(1, candidates.size());
	}


	public void testForHS256()
		throws Exception {

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
			JWSAlgorithm.HS256,
			new ImmutableJWKSet(new JWKSet(new OctetSequenceKey.Builder(secret).build())));

		assertEquals(JWSAlgorithm.HS256, keySelector.getExpectedJWSAlgorithm());
		assertNotNull(keySelector.getJWKSource());

		// Test JWK matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.HS256).build());
		assertTrue(m.getKeyTypes().contains(KeyType.OCT));
		assertTrue(m.getAlgorithms().contains(JWSAlgorithm.HS256));

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build());
		assertNull(m);

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("1").build());
		assertNull(m);

		// Select for good header
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), null);
		Assert.assertArrayEquals(secret, candidates.get(0).getEncoded());
		assertEquals(1, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("100").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWS alg
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());
	}
}
