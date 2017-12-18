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

package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.Security;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import junit.framework.TestCase;


/**
 * JCA provider support tests.
 */
public class JCASupportTest extends TestCase {


	public void testUnlimitedCrypto() {

		String msg = "Unlimited JCE cryptography strength not supported, go to http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html";

		assertTrue(msg, JCASupport.isUnlimitedStrength());
	}


	public void testJWSSupport_Default_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS512));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS512));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS512));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS256));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES512));
	}


	public void testJWSSupport_SUN_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS256, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS384, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS512, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS256, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS384, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS256, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS384, Security.getProvider("SunRsaSign")));

		if (Security.getProvider("SunEC") != null) {
			// Not supported on OpenJDK
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES256, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES384, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES512, Security.getProvider("SunEC")));
		}
	}


	public void testJWSSupport_Default_Java_8() {

		if (! System.getProperty("java.version").startsWith("1.8")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS512));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS512));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS512));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS256));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES256));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES384));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES512));
	}


	public void testJWSSupport_SUN_Java_8() {

		if (! System.getProperty("java.version").startsWith("1.8")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS256, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS384, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS512, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS256, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS384, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS256, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported(JWSAlgorithm.PS384, Security.getProvider("SunRsaSign")));

		if (Security.getProvider("SunEC") != null) {
			// Not supported on OpenJDK
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES256, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES384, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWSAlgorithm.ES512, Security.getProvider("SunEC")));
		}
	}


	public void testJWSSupport_BC() {

		Provider bc = BouncyCastleProviderSingleton.getInstance();

		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS256, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS384, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.HS512, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS256, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS384, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.RS512, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.PS256, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.PS384, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.PS512, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES256, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES384, bc));
		assertTrue(JCASupport.isSupported(JWSAlgorithm.ES512, bc));
	}


	public void testJWESupport_Default_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA1_5));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP_256));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.A128KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A192KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A256KW));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS512_A256KW));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A128KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A192KW));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A256KW));

		assertFalse(JCASupport.isSupported(JWEAlgorithm.A128GCMKW));
		assertFalse(JCASupport.isSupported(JWEAlgorithm.A192GCMKW));
		assertFalse(JCASupport.isSupported(JWEAlgorithm.A256GCMKW));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.DIR));
	}


	public void testJWESupport_SUN_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA1_5, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP_256, Security.getProvider("SunJCE")));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.A128KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A192KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A256KW, Security.getProvider("SunJCE")));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS256_A128KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS384_A192KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.PBES2_HS512_A256KW, Security.getProvider("SunJCE")));

		if (Security.getProvider("SunEC") != null) {
			// Not supported on OpenJDK
			assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A128KW, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A192KW, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A256KW, Security.getProvider("SunEC")));
		}

		assertFalse(JCASupport.isSupported(JWEAlgorithm.A128GCMKW, Security.getProvider("SUN")));
		assertFalse(JCASupport.isSupported(JWEAlgorithm.A192GCMKW, Security.getProvider("SUN")));
		assertFalse(JCASupport.isSupported(JWEAlgorithm.A256GCMKW, Security.getProvider("SUN")));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.DIR, Security.getProvider("SUN")));
	}


	public void testJWESupport_BC() {

		Provider bc = BouncyCastleProviderSingleton.getInstance();

		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA1_5, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.RSA_OAEP_256, bc));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.A128KW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A192KW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A256KW, bc));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A128KW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A192KW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.ECDH_ES_A256KW, bc));

		assertTrue(JCASupport.isSupported(JWEAlgorithm.A128GCMKW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A192GCMKW, bc));
		assertTrue(JCASupport.isSupported(JWEAlgorithm.A256GCMKW, bc));
	}


	public void testEncryptionMethodSupport_Default_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(EncryptionMethod.A128CBC_HS256));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A192CBC_HS384));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A256CBC_HS512));

		assertFalse(JCASupport.isSupported(EncryptionMethod.A128GCM));
		assertFalse(JCASupport.isSupported(EncryptionMethod.A192GCM));
		assertFalse(JCASupport.isSupported(EncryptionMethod.A256GCM));
	}


	public void testEncryptionMethodSupport_SUN_Java_7() {

		if (! System.getProperty("java.version").startsWith("1.7")) {
			return;
		}

		assertTrue(JCASupport.isSupported(EncryptionMethod.A128CBC_HS256, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A192CBC_HS384, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A256CBC_HS512, Security.getProvider("SunJCE")));

		assertFalse(JCASupport.isSupported(EncryptionMethod.A128GCM, Security.getProvider("SunJCE")));
		assertFalse(JCASupport.isSupported(EncryptionMethod.A192GCM, Security.getProvider("SunJCE")));
		assertFalse(JCASupport.isSupported(EncryptionMethod.A256GCM, Security.getProvider("SunJCE")));
	}


	public void testEncryptionMethodSupport_BC() {

		Provider bc = BouncyCastleProviderSingleton.getInstance();

		assertTrue(JCASupport.isSupported(EncryptionMethod.A128CBC_HS256, bc));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A192CBC_HS384, bc));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A256CBC_HS512, bc));

		assertTrue(JCASupport.isSupported(EncryptionMethod.A128GCM, bc));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A192GCM, bc));
		assertTrue(JCASupport.isSupported(EncryptionMethod.A256GCM, bc));
	}
	
	
	public void testAlgNoneAlwaysSupported() {
		
		assertTrue(JCASupport.isSupported(new JWSAlgorithm("none")));
	}
	
	
	public void testJOSEAlgorithmSupport_Default_Java_8() {
		
		if (! System.getProperty("java.version").startsWith("1.8")) {
			return;
		}
		
		// JWS
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS256));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS384));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS512));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS256));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS384));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS512));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS512));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS256));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS384));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES256));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES384));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES512));
		
		// JWE alg
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA1_5));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA_OAEP));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA_OAEP_256));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A128KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A192KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A256KW));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS512_A256KW));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A128KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A192KW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A256KW));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A128GCMKW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A192GCMKW));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A256GCMKW));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.DIR));
		
		// JWE enc
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A128CBC_HS256));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A192CBC_HS384));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A256CBC_HS512));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A128GCM));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A192GCM));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A256GCM));
	}
	
	
	public void testJOSEAlgorithmSupport_SUN_Java8() {
		
		if (! System.getProperty("java.version").startsWith("1.8")) {
			return;
		}
		
		// JWS
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS256, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS384, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.HS512, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS256, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS384, Security.getProvider("SunRsaSign")));
		assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.RS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS512, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS256, Security.getProvider("SunRsaSign")));
		assertFalse(JCASupport.isSupported((Algorithm) JWSAlgorithm.PS384, Security.getProvider("SunRsaSign")));
		
		if (Security.getProvider("SunEC") != null) {
			// Not supported on OpenJDK
			assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES256, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES384, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported((Algorithm) JWSAlgorithm.ES512, Security.getProvider("SunEC")));
		}
		
		// JWE alg
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA1_5, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA_OAEP, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.RSA_OAEP_256, Security.getProvider("SunJCE")));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A128KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A192KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.A256KW, Security.getProvider("SunJCE")));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS256_A128KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS384_A192KW, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.PBES2_HS512_A256KW, Security.getProvider("SunJCE")));
		
		if (Security.getProvider("SunEC") != null) {
			// Not supported on OpenJDK
			assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A128KW, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A192KW, Security.getProvider("SunEC")));
			assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.ECDH_ES_A256KW, Security.getProvider("SunEC")));
		}
		
		assertFalse(JCASupport.isSupported((Algorithm) JWEAlgorithm.A128GCMKW, Security.getProvider("SUN")));
		assertFalse(JCASupport.isSupported((Algorithm) JWEAlgorithm.A192GCMKW, Security.getProvider("SUN")));
		assertFalse(JCASupport.isSupported((Algorithm) JWEAlgorithm.A256GCMKW, Security.getProvider("SUN")));
		
		assertTrue(JCASupport.isSupported((Algorithm) JWEAlgorithm.DIR, Security.getProvider("SUN")));
		
		// JWE enc
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A128CBC_HS256, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A192CBC_HS384, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A256CBC_HS512, Security.getProvider("SunJCE")));
		
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A128GCM, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A192GCM, Security.getProvider("SunJCE")));
		assertTrue(JCASupport.isSupported((Algorithm) EncryptionMethod.A256GCM, Security.getProvider("SunJCE")));
	}
}
