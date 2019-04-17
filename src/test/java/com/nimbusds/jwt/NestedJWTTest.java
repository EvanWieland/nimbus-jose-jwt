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

package com.nimbusds.jwt;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;


public class NestedJWTTest extends TestCase {
	
	
	// https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt
	public void testNestedExample_keysJWK()
		throws Exception {
		
		RSAKey senderJWK = new RSAKeyGenerator(2048)
			.keyID("123")
			.keyUse(KeyUse.SIGNATURE)
			.generate();
		RSAKey senderPublicJWK = senderJWK.toPublicJWK();
		
		
		RSAKey recipientJWK = new RSAKeyGenerator(2048)
			.keyID("456")
			.keyUse(KeyUse.ENCRYPTION)
			.generate();
		RSAKey recipientPublicJWK = recipientJWK.toPublicJWK();
		
		
		// Create JWT
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(senderJWK.getKeyID())
				.build(),
			new JWTClaimsSet.Builder()
				.subject("alice")
				.issueTime(new Date())
				.issuer("https://c2id.com")
				.build());

		// Sign the JWT
		signedJWT.sign(new RSASSASigner(senderJWK));

		// Create JWE object with signed JWT as payload
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.contentType("JWT") // required to indicate nested JWT
				.build(),
			new Payload(signedJWT));

		// Encrypt with the recipient's public key
		RSAEncrypter encrypter = new RSAEncrypter(recipientPublicJWK);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		// Serialise to JWE compact form
		String jweString = jweObject.serialize();
		
		
		// Parse the JWE string
		JWEObject receivedJWEObject = JWEObject.parse(jweString);

		// Decrypt with private key
		RSADecrypter decrypter = new RSADecrypter(recipientJWK);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		receivedJWEObject.decrypt(decrypter);

		// Extract payload
		SignedJWT receivedSignedJWT = receivedJWEObject.getPayload().toSignedJWT();
		
		assertNotNull("Payload not a signed JWT", signedJWT);

		// Check the signature
		assertTrue(receivedSignedJWT.verify(new RSASSAVerifier(senderPublicJWK)));

		// Retrieve the JWT claims...
		assertEquals("alice", receivedSignedJWT.getJWTClaimsSet().getSubject());
	}
	
	
	public void testNestedExample_keysJava()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		
		KeyPair keyPair = gen.generateKeyPair();
		
		RSAPrivateKey senderKey = (RSAPrivateKey)keyPair.getPrivate();
		RSAPublicKey senderPublicKey = (RSAPublicKey)keyPair.getPublic();
		
		keyPair = gen.generateKeyPair();
		RSAPrivateKey recipientKey = (RSAPrivateKey)keyPair.getPrivate();
		RSAPublicKey recipientPublicKey = (RSAPublicKey)keyPair.getPublic();
		
		
		// Create JWT
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.build(),
			new JWTClaimsSet.Builder()
				.subject("alice")
				.issueTime(new Date())
				.issuer("https://c2id.com")
				.build());

		// Sign the JWT
		signedJWT.sign(new RSASSASigner(senderKey));

		// Create JWE object with signed JWT as payload
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.contentType("JWT") // required to indicate nested JWT
				.build(),
			new Payload(signedJWT));

		// Encrypt with the recipient's public key
		RSAEncrypter encrypter = new RSAEncrypter(recipientPublicKey);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		// Serialise to JWE compact form
		String jweString = jweObject.serialize();
		
		
		// Parse the JWE string
		JWEObject receivedJWEObject = JWEObject.parse(jweString);

		// Decrypt with private key
		RSADecrypter decrypter = new RSADecrypter(recipientKey);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		receivedJWEObject.decrypt(decrypter);

		// Extract payload
		SignedJWT receivedSignedJWT = receivedJWEObject.getPayload().toSignedJWT();
		
		assertNotNull("Payload not a signed JWT", signedJWT);

		// Check the signature
		assertTrue(receivedSignedJWT.verify(new RSASSAVerifier(senderPublicKey)));

		// Retrieve the JWT claims...
		assertEquals("alice", receivedSignedJWT.getJWTClaimsSet().getSubject());
	}
}
