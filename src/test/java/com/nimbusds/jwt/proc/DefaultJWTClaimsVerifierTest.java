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

package com.nimbusds.jwt.proc;


import java.util.Arrays;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;


public class DefaultJWTClaimsVerifierTest extends TestCase {
	
	
	public void testDefaultConstructor() {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertFalse(verifier.requiresIssuedAtTime());
		assertFalse(verifier.requiresExpirationTime());
		assertFalse(verifier.requiresNotBeforeTime());
		assertNull(verifier.getAcceptedIssuer());
		assertNull(verifier.getAcceptedAudience());
		assertEquals(60, verifier.getMaxClockSkew());
	}


	public void testValidNoClaims()
		throws BadJOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNotExpired()
		throws BadJOSEException {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testExpired() {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testNbfAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNbfDenied() {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}


	public void testAllAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testDefaultClockSkewConstant() {

		assertEquals(60, DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS);
	}


	public void testExpirationWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAgo = new Date(now.getTime() - 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().expirationTime(thirtySecondsAgo).build());
	}


	public void testNotBeforeWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAhead = new Date(now.getTime() + 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().notBeforeTime(thirtySecondsAhead).build());
	}


	public void testClockSkew() {

		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertEquals(DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS, verifier.getMaxClockSkew());
		verifier.setMaxClockSkew(120);
		assertEquals(120, verifier.getMaxClockSkew());
	}
	
	
	public void testIssuer() {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertNull(verifier.getAcceptedIssuer());
		verifier.setAcceptedIssuer(iss);
		assertEquals(iss, verifier.getAcceptedIssuer());
	}
	
	
	public void testAudience() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertNull(verifier.getAcceptedAudience());
		verifier.setAcceptedAudience(aud);
		assertEquals(aud, verifier.getAcceptedAudience());
	}
	
	
	public void testIssuerMissing() {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.setAcceptedIssuer(iss);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT issuer missing", e.getMessage());
		}
	}
	
	
	public void testIssuerNotAccepted() {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.setAcceptedIssuer(iss);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().issuer("https://example.com").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT issuer not accepted: https://example.com", e.getMessage());
		}
	}
	
	
	public void testAudienceMissing() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.setAcceptedAudience(aud);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience missing", e.getMessage());
		}
	}
	
	
	public void testAudienceNotAccepted() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.setAcceptedAudience(aud);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience("456").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience not accepted: [456]", e.getMessage());
		}
	}
	
	
	public void testAudienceNotAccepted_multi() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.setAcceptedAudience(aud);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience(Arrays.asList("456", "789")).build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience not accepted: [456, 789]", e.getMessage());
		}
	}
	
	
	public void testRequiresIAT() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertFalse(verifier.requiresIssuedAtTime());
		verifier.requiresIssuedAtTime(true);
		assertTrue(verifier.requiresIssuedAtTime());
		
		verifier.verify(new JWTClaimsSet.Builder().issueTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT issued-at time missing", e.getMessage());
		}
	}
	
	
	public void testRequiresEXP() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertFalse(verifier.requiresExpirationTime());
		verifier.requiresExpirationTime(true);
		assertTrue(verifier.requiresExpirationTime());
		
		verifier.verify(new JWTClaimsSet.Builder().expirationTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT expiration time missing", e.getMessage());
		}
	}
	
	
	public void testRequiresNBF() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertFalse(verifier.requiresNotBeforeTime());
		verifier.requiresNotBeforeTime(true);
		assertTrue(verifier.requiresNotBeforeTime());
		
		verifier.verify(new JWTClaimsSet.Builder().notBeforeTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT not-before time missing", e.getMessage());
		}
	}
}
