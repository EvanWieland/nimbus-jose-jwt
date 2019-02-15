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


import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;


public class ExampleTest extends TestCase {
	
	
	// http://dev.connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
	public void testRSAExample()
		throws Exception {
		
		// RSA signatures require a public and private RSA key pair,
		// the public key must be made known to the JWS recipient to
		// allow the signatures to be verified
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("123")
			.generate();
		RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(rsaJWK);

		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			new Payload("In RSA we trust!"));

		// Compute the RSA signature
		jwsObject.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
		// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
		// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
		// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
		String s = jwsObject.serialize();

		// To parse the JWS and verify it, e.g. on client-side
		jwsObject = JWSObject.parse(s);
		
		JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
		
		assertTrue(jwsObject.verify(verifier));
		
		assertEquals("In RSA we trust!", jwsObject.getPayload().toString());
	}
	
	
	public void testECExample()
		throws Exception {
		
		// Generate an EC key pair
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyID("123")
			.generate();
		ECKey ecPublicJWK = ecJWK.toPublicJWK();

		// Create the EC signer
		JWSSigner signer = new ECDSASigner(ecJWK);

		// Creates the JWS object with payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
			new Payload("Elliptic cure"));

		// Compute the EC signature
		jwsObject.sign(signer);

		// Serialize the JWS to compact form
		String s = jwsObject.serialize();


		// The recipient creates a verifier with the public EC key
		JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
		
		// Verify the EC signature
		assertTrue("ES256 signature verified", jwsObject.verify(verifier));
		assertEquals("Elliptic cure", jwsObject.getPayload().toString());
		
	}
}
