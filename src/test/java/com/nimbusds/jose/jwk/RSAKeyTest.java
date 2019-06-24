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

package com.nimbusds.jose.jwk;


import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.*;


/**
 * Tests the RSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-06-24
 */
public class RSAKeyTest extends TestCase {


	// Test parameters are from JPSK spec


	private static final String n =
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";


	private static final String e = "AQAB";


	private static final String d =
		"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
			"M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
			"wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
			"_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
			"nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
			"me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";


	private static final String p =
		"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
			"nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
			"WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";


	private static final String q =
		"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
			"qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
			"kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";


	private static final String dp =
		"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
			"YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
			"YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";


	private static final String dq =
		"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
			"vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
			"GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";


	private static final String qi =
		"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
			"UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
			"yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";


	public void testConstructAndSerialize()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = null; // not specified here
		
		// Recreate PrivateKey
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = factory.generatePrivate(new RSAPrivateKeySpec(new Base64URL(n).decodeToBigInteger(), new Base64URL(d).decodeToBigInteger()));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			new Base64URL(p), new Base64URL(q),
			new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			null,
			privateKey,
			KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
			x5u, x5t, x5t256, x5c,
			keyStore);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());
		
		// private key generated from key material, not PrivateKey ref
		assertNotSame(privateKey, key.toPrivateKey());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		// Test conversion to public JWK

		key = key.toPublicJWK();
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertNull(key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertFalse(key.isPrivate());
	}


	public void testConstructorAndSerialize_deprecated()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = null; // not specified here

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			new Base64URL(p), new Base64URL(q),
			new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			null,
			KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
			x5u, x5t, x5t256, x5c);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		// Test conversion to public JWK

		key = key.toPublicJWK();
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertNull(key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertFalse(key.isPrivate());
	}


	public void testBase64Builder()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc");
		List<Base64> x5c = null; // not specified here

		RSAKey key = new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
			.privateExponent(new Base64URL(d))
			.firstPrimeFactor(new Base64URL(p))
			.secondPrimeFactor(new Base64URL(q))
			.firstFactorCRTExponent(new Base64URL(dp))
			.secondFactorCRTExponent(new Base64URL(dq))
			.firstCRTCoefficient(new Base64URL(qi))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertSHA256Thumbprint(x5t256)
			.x509CertChain(x5c)
			.build();

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());
		assertNull(key.getKeyStore());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}


	public void testObjectBuilder()
		throws Exception {

		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = null; // not specified here

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		RSAKey key = new RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyUse(null)
			.keyOperations(ops)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertSHA256Thumbprint(x5t256)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());
		assertEquals(keyStore, key.getKeyStore());

		assertTrue(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger()));
		assertTrue(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger()));

		assertTrue(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger()));

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = RSAKey.parse(jwkString);

		// Test getters
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());
		assertNull(key.getKeyStore());

		assertTrue(publicKey.getModulus().equals(key.getModulus().decodeToBigInteger()));
		assertTrue(publicKey.getPublicExponent().equals(key.getPublicExponent().decodeToBigInteger()));

		assertTrue(privateKey.getPrivateExponent().equals(key.getPrivateExponent().decodeToBigInteger()));

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}
	
	
	public void testCopyBuilder()
		throws Exception {
		
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = null; // not specified here
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		RSAKey key = new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
			.privateExponent(new Base64URL(d))
			.firstPrimeFactor(new Base64URL(p))
			.secondPrimeFactor(new Base64URL(q))
			.firstFactorCRTExponent(new Base64URL(dp))
			.secondFactorCRTExponent(new Base64URL(dq))
			.firstCRTCoefficient(new Base64URL(qi))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertSHA256Thumbprint(x5t256)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();
		
		// Copy
		key = new RSAKey.Builder(key).build();
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertNull(key.getX509CertChain());
		assertNull(key.getParsedX509CertChain());
		assertEquals(keyStore, key.getKeyStore());
		
		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());
		
		assertEquals(new Base64URL(d), key.getPrivateExponent());
		
		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());
		
		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());
		
		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());
		
		assertTrue(key.getOtherPrimes().isEmpty());
		
		assertTrue(key.isPrivate());
	}


	public void testRSAPublicKeyExportAndImport()
		throws Exception {


		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e),
			null, null, null, null,
			null, null, null, null, null);

		// Public key export
		RSAPublicKey pubKey = key.toRSAPublicKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());


		// Public key import
		key = new RSAKey(pubKey, null, null, null, null, null, null, null, null, null);
		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());
	}


	public void testRSAPrivateKeyExportAndImport()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			new Base64URL(p), new Base64URL(q),
			new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			null,
			KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
			null, null, null, null);

		// Private key export with CRT (2nd form)
		RSAPrivateKey privKey = key.toRSAPrivateKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), privKey.getModulus());
		assertEquals(new Base64URL(d).decodeToBigInteger(), privKey.getPrivateExponent());

		assertTrue(privKey instanceof RSAPrivateCrtKey);
		RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey) privKey;
		assertEquals(new Base64URL(e).decodeToBigInteger(), privCrtKey.getPublicExponent());
		assertEquals(new Base64URL(p).decodeToBigInteger(), privCrtKey.getPrimeP());
		assertEquals(new Base64URL(q).decodeToBigInteger(), privCrtKey.getPrimeQ());
		assertEquals(new Base64URL(dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
		assertEquals(new Base64URL(dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
		assertEquals(new Base64URL(qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());


		// Key pair export
		KeyPair pair = key.toKeyPair();

		RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());

		privKey = (RSAPrivateKey) pair.getPrivate();
		assertEquals(new Base64URL(n).decodeToBigInteger(), privKey.getModulus());
		assertEquals(new Base64URL(d).decodeToBigInteger(), privKey.getPrivateExponent());

		assertTrue(privKey instanceof RSAPrivateCrtKey);
		privCrtKey = (RSAPrivateCrtKey) privKey;
		assertEquals(new Base64URL(e).decodeToBigInteger(), privCrtKey.getPublicExponent());
		assertEquals(new Base64URL(p).decodeToBigInteger(), privCrtKey.getPrimeP());
		assertEquals(new Base64URL(q).decodeToBigInteger(), privCrtKey.getPrimeQ());
		assertEquals(new Base64URL(dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
		assertEquals(new Base64URL(dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
		assertEquals(new Base64URL(qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());


		// Key pair import, 1st private form
		key = new RSAKey(pubKey, privKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null, null, null);
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertNull(key.getFirstPrimeFactor());
		assertNull(key.getSecondPrimeFactor());

		assertNull(key.getFirstFactorCRTExponent());
		assertNull(key.getSecondFactorCRTExponent());

		assertNull(key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());


		// Key pair import, 2nd private form
		key = new RSAKey(pubKey, privCrtKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null,null, null, null);
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());

		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());

		assertEquals(new Base64URL(d), key.getPrivateExponent());

		assertEquals(new Base64URL(p), key.getFirstPrimeFactor());
		assertEquals(new Base64URL(q), key.getSecondPrimeFactor());

		assertEquals(new Base64URL(dp), key.getFirstFactorCRTExponent());
		assertEquals(new Base64URL(dq), key.getSecondFactorCRTExponent());

		assertEquals(new Base64URL(qi), key.getFirstCRTCoefficient());

		assertTrue(key.getOtherPrimes().isEmpty());

		assertTrue(key.isPrivate());
	}


	public void testPublicKeyExportAndImport()
		throws Exception {


		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e),
			null, null, null, null,
			null, null, null, null, null);

		assertTrue(key instanceof AsymmetricJWK);

		// Public key export
		RSAPublicKey pubKey = (RSAPublicKey) key.toPublicKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), pubKey.getModulus());
		assertEquals(new Base64URL(e).decodeToBigInteger(), pubKey.getPublicExponent());
		assertEquals("RSA", pubKey.getAlgorithm());


		// Public key import
		key = new RSAKey(pubKey, null, null, null, null, null, null, null, null, null);
		assertEquals(new Base64URL(n), key.getModulus());
		assertEquals(new Base64URL(e), key.getPublicExponent());
	}


	public void testPrivateKeyExport()
		throws Exception {

		RSAKey key = new RSAKey(new Base64URL(n), new Base64URL(e), new Base64URL(d),
			new Base64URL(p), new Base64URL(q),
			new Base64URL(dp), new Base64URL(dq), new Base64URL(qi),
			null,
			KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
			null, null, null, null);

		assertTrue(key instanceof AsymmetricJWK);

		// Private key export with CRT (2nd form)
		RSAPrivateKey privKey = (RSAPrivateKey ) key.toPrivateKey();
		assertEquals(new Base64URL(n).decodeToBigInteger(), privKey.getModulus());
		assertEquals(new Base64URL(d).decodeToBigInteger(), privKey.getPrivateExponent());

		assertTrue(privKey instanceof RSAPrivateCrtKey);
		RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey) privKey;
		assertEquals(new Base64URL(e).decodeToBigInteger(), privCrtKey.getPublicExponent());
		assertEquals(new Base64URL(p).decodeToBigInteger(), privCrtKey.getPrimeP());
		assertEquals(new Base64URL(q).decodeToBigInteger(), privCrtKey.getPrimeQ());
		assertEquals(new Base64URL(dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
		assertEquals(new Base64URL(dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
		assertEquals(new Base64URL(qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());
	}


	public void testParseSomeKey()
		throws Exception {

		String json = "{\n" +
			"      \"kty\": \"RSA\",\n" +
			"      \"n\": \"f9BhJgBgoDKGcYLh+xl6qulS8fUFYxuWSz4Sk+7Yw2Wv4Wroe3yLzJjqEqH8IFR0Ow8Sr3pZo0IwOPcWHQZMQr0s2kWbKSpBrnDsK4vsdBvoP1jOaylA9XsHPF9EZ/1F+eQkVHoMsc9eccf0nmr3ubD56LjSorTsbOuxi8nqEzisvhDHthacW/qxbpR/jojQNfdWyDz6NC+MA2LYYpdsw5TG8AVdKjobHWfQvXYdcpvQRkDDhgbwQt1KD8ZJ1VL+nJcIfSppPzCbfM2eY78y/c4euL/SQPs7kGf+u3R9hden7FjMUuIFZoAictiBgjVZ/JOaK+C++L+IsnCKqauhEQ==\",\n" +
			"      \"e\": \"AQAB\",\n" +
			"      \"alg\": \"RS256\"\n" +
			"}";

		RSAKey key = RSAKey.parse(json);

		assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());

		assertEquals(256, key.getModulus().decode().length);
	}


	public void testKeyConversionRoundTrip()
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey rsaPublicKeyIn = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey rsaPrivateKeyIn = (RSAPrivateKey) keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey.Builder(rsaPublicKeyIn).privateKey(rsaPrivateKeyIn).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK.getPrivateExponent().decodeToBigInteger());

		// Convert back to Java RSA keys
		RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
		RSAPrivateKey rsaPrivateKeyOut = rsaJWK.toRSAPrivateKey();

		assertEquals(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaPublicKeyOut.getPublicExponent());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaPublicKeyOut.getModulus());

		assertEquals(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaPrivateKeyOut.getPrivateExponent());

		// Compare encoded forms
		assertEquals("Public RSA", Base64.encode(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
		assertEquals("Private RSA", Base64.encode(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());

		RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK2.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK2.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK2.getPrivateExponent().decodeToBigInteger());
	}


	public void testKeyConversionRoundTripWithCRTParams()
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair keyPair = keyGen.genKeyPair();
		RSAPublicKey rsaPublicKeyIn = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateCrtKey rsaPrivateKeyIn = (RSAPrivateCrtKey) keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey(rsaPublicKeyIn, rsaPrivateKeyIn, null, null, null, null,null, null, null, null, null);

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK.getPrivateExponent().decodeToBigInteger());

		// Compare CRT params
		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaJWK.getFirstPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaJWK.getSecondPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK.getFirstFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK.getSecondFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK.getFirstCRTCoefficient().decodeToBigInteger());
		assertTrue(rsaJWK.getOtherPrimes() == null || rsaJWK.getOtherPrimes().isEmpty());

		// Convert back to Java RSA keys
		RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
		RSAPrivateCrtKey rsaPrivateKeyOut = (RSAPrivateCrtKey) rsaJWK.toRSAPrivateKey();

		assertEquals(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaPublicKeyOut.getPublicExponent());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaPublicKeyOut.getModulus());

		assertEquals(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaPrivateKeyOut.getPrivateExponent());

		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaPrivateKeyOut.getPrimeP());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaPrivateKeyOut.getPrimeQ());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaPrivateKeyOut.getPrimeExponentP());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaPrivateKeyOut.getPrimeExponentQ());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaPrivateKeyOut.getCrtCoefficient());

		// Compare encoded forms
		assertEquals("Public RSA", Base64.encode(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
		assertEquals("Private RSA", Base64.encode(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());

		RSAKey rsaJWK2 = new RSAKey.Builder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

		// Compare JWK values with original Java RSA values
		assertEquals(rsaPublicKeyIn.getPublicExponent(), rsaJWK2.getPublicExponent().decodeToBigInteger());
		assertEquals(rsaPublicKeyIn.getModulus(), rsaJWK2.getModulus().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK2.getPrivateExponent().decodeToBigInteger());

		// Compare CRT params
		assertEquals(rsaPrivateKeyIn.getPrimeP(), rsaJWK2.getFirstPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeQ(), rsaJWK2.getSecondPrimeFactor().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK2.getFirstFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK2.getSecondFactorCRTExponent().decodeToBigInteger());
		assertEquals(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK2.getFirstCRTCoefficient().decodeToBigInteger());
		assertTrue(rsaJWK2.getOtherPrimes() == null || rsaJWK2.getOtherPrimes().isEmpty());
	}


	public void testKeyUseConsistentWithOps() {

		KeyUse use = KeyUse.SIGNATURE;

		Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		JWK jwk = new RSAKey(new Base64URL(n), new Base64URL(e), use, ops, null, null, null, null, null, null, null);
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
		
		jwk = new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
			.keyUse(use)
			.keyOperations(ops)
			.build();
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
		
		// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/226/jwk-constructor-erroneously-throws
		use = KeyUse.SIGNATURE;
		ops = Collections.singleton(KeyOperation.SIGN);
		jwk = new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
			.privateExponent(new Base64URL(d))
			.keyUse(use)
			.keyOperations(ops)
			.build();
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
	}
	
	
	public void testRejectKeyUseNotConsistentWithOps() {
		
		KeyUse use = KeyUse.SIGNATURE;
		
		Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT));
		
		try {
			new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
				.keyUse(use)
				.keyOperations(ops)
				.build();
		} catch (IllegalStateException e) {
			assertEquals("The key use \"use\" and key options \"key_opts\" parameters are not consistent, see RFC 7517, section 4.3", e.getMessage());
		}
	}
	
	
	public void testRejectEmptyCertificateChain() {
		
		try {
			new RSAKey.Builder(new Base64URL(n), new Base64URL(e))
				.x509CertChain(Collections.<Base64>emptyList())
				.build();
		} catch (IllegalStateException e) {
			assertEquals("The X.509 certificate chain \"x5c\" must not be empty", e.getMessage());
		}
	}


	public void testParseCookbookExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-3.4

		String json = "{" +
			"\"kty\": \"RSA\"," +
			"\"kid\": \"bilbo.baggins@hobbiton.example\"," +
			"\"use\": \"sig\"," +
			"\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw\"," +
			"\"e\": \"AQAB\"," +
			"\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ\"," +
			"\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
			"aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
			"peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
			"bUq0k\"," +
			"\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
			"8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
			"V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
			"s7pFc\"," +
			"\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
			"1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
			"-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
			"59ehik\"," +
			"\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
			"AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
			"bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
			"T1cYF8\"," +
			"\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
			"ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
			"jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
			"z8aaI4\"" +
			"}";

		RSAKey jwk = RSAKey.parse(json);

		assertEquals(KeyType.RSA, jwk.getKeyType());
		assertEquals("bilbo.baggins@hobbiton.example", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());

		assertEquals("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ", jwk.getPrivateExponent().toString());

		assertEquals("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
			"aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
			"peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
			"bUq0k", jwk.getFirstPrimeFactor().toString());

		assertEquals("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
			"8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
			"V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
			"s7pFc", jwk.getSecondPrimeFactor().toString());

		assertEquals("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
			"1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
			"-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
			"59ehik", jwk.getFirstFactorCRTExponent().toString());

		assertEquals("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
			"AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
			"bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
			"T1cYF8", jwk.getSecondFactorCRTExponent().toString());

		assertEquals("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
			"ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
			"jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
			"z8aaI4", jwk.getFirstCRTCoefficient().toString());

		// Convert to Java RSA key object
		RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
		RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

		jwk = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

		assertEquals("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
			"HdrNP5zw", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
			"OpBrQzwQ", jwk.getPrivateExponent().toString());
	}


	public void testParseCookbookExample2()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.1.1

		String json = "{" +
			"\"kty\":\"RSA\"," +
			"\"kid\":\"frodo.baggins@hobbiton.example\"," +
			"\"use\":\"enc\"," +
			"\"n\":\"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
			"VotGlvMQ\"," +
			"\"e\":\"AQAB\"," +
			"\"d\":\"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
			"pzj85bQQ\"," +
			"\"p\":\"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
			"oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
			"7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
			"2VFmU\"," +
			"\"q\":\"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
			"F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
			"9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
			"d6Et0\"," +
			"\"dp\":\"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
			"QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
			"RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
			"lo0rYU\"," +
			"\"dq\":\"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
			"pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
			"CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
			"TkXlHE\"," +
			"\"qi\":\"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
			"lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
			"Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
			"2bQ_mM\"" +
			"}";

		RSAKey jwk = RSAKey.parse(json);

		assertEquals(KeyType.RSA, jwk.getKeyType());
		assertEquals("frodo.baggins@hobbiton.example", jwk.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());

		assertEquals("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
			"VotGlvMQ", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
			"pzj85bQQ", jwk.getPrivateExponent().toString());

		assertEquals("2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
			"oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
			"7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
			"2VFmU", jwk.getFirstPrimeFactor().toString());

		assertEquals("te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
			"F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
			"9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
			"d6Et0", jwk.getSecondPrimeFactor().toString());

		assertEquals("UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
			"QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
			"RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
			"lo0rYU", jwk.getFirstFactorCRTExponent().toString());

		assertEquals("iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
			"pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
			"CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
			"TkXlHE", jwk.getSecondFactorCRTExponent().toString());

		assertEquals("kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
			"lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
			"Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
			"2bQ_mM", jwk.getFirstCRTCoefficient().toString());

		// Convert to Java RSA key object
		RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
		RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

		jwk = new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build();

		assertEquals("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
			"VotGlvMQ", jwk.getModulus().toString());

		assertEquals("AQAB", jwk.getPublicExponent().toString());

		assertEquals("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
			"pzj85bQQ", jwk.getPrivateExponent().toString());
	}


	// Test vector from https://tools.ietf.org/html/rfc7638#section-3.1
	public void testComputeThumbprint()
		throws Exception {

		String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
			"aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
			"FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
			"GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
			"91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
			"BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

		RSAKey rsaKey = RSAKey.parse(json);

		Base64URL thumbprint = rsaKey.computeThumbprint();

		assertEquals(thumbprint, rsaKey.computeThumbprint("SHA-256"));

		assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint.toString());
		assertEquals(256 / 8, thumbprint.decode().length);
	}


	public void testComputeThumbprintSHA1()
		throws Exception {

		String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
			"aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
			"FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
			"GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
			"91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
			"BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

		RSAKey rsaKey = RSAKey.parse(json);

		Base64URL thumbprint = rsaKey.computeThumbprint("SHA-1");

		assertEquals(160 / 8, thumbprint.decode().length);
	}


	// Test vector from https://tools.ietf.org/html/rfc7638#section-3.1
	public void testThumbprintAsKeyID()
		throws Exception {

		String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
			"aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
			"FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
			"GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
			"91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
			"BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

		RSAKey rsaKey = RSAKey.parse(json);

		rsaKey = new RSAKey.Builder(rsaKey.getModulus(), rsaKey.getPublicExponent())
			.keyIDFromThumbprint()
			.build();

		assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", rsaKey.getKeyID());
	}


	public void testThumbprintSHA1AsKeyID()
		throws Exception {

		String json = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
			"aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
			"FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
			"GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
			"91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
			"BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

		RSAKey rsaKey = RSAKey.parse(json);

		rsaKey = new RSAKey.Builder(rsaKey.getModulus(), rsaKey.getPublicExponent())
			.keyIDFromThumbprint("SHA-1")
			.build();

		assertEquals(160 / 8, new Base64URL(rsaKey.getKeyID()).decode().length);
	}


	public void testSize() {

		assertEquals(2048, new RSAKey.Builder(new Base64URL(n), new Base64URL(e)).build().size());
	}
	
	
	// For private RSA keys as PKCS#11 handle
	public void testPrivateKeyHandle()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		final KeyPair kp = gen.generateKeyPair();
		
		RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
		PrivateKey privateKey = new PrivateKey() {
			// simulate private PKCS#11 key with inaccessible key material
			@Override
			public String getAlgorithm() {
				return kp.getPrivate().getAlgorithm();
			}
			
			
			@Override
			public String getFormat() {
				return kp.getPrivate().getFormat();
			}
			
			
			@Override
			public byte[] getEncoded() {
				return new byte[0];
			}
		};
		
		RSAKey rsaJWK = new RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyID("1")
			.build();
		
		assertNotNull(rsaJWK.toPublicKey());
		assertEquals(privateKey, rsaJWK.toPrivateKey());
		assertTrue(rsaJWK.isPrivate());
		
		KeyPair kpOut = rsaJWK.toKeyPair();
		assertNotNull(kpOut.getPublic());
		assertEquals(privateKey, kpOut.getPrivate());
		
		JSONObject json = rsaJWK.toJSONObject();
		assertEquals("RSA", json.get("kty"));
		assertEquals("1", json.get("kid"));
		assertEquals(Base64URL.encode(publicKey.getPublicExponent()).toString(), json.get("e"));
		assertEquals(Base64URL.encode(publicKey.getModulus()).toString(), json.get("n"));
		assertEquals(4, json.size());
	}
	
	
	public void testParseFromX509Cert()
		throws Exception {
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		RSAKey rsaKey = RSAKey.parse(cert);
		
		assertEquals(KeyUse.ENCRYPTION, rsaKey.getKeyUse());
		assertEquals(cert.getSerialNumber().toString(10), rsaKey.getKeyID());
		assertNotSame(pemEncodedCert, rsaKey.getX509CertChain().get(0).toString());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertEquals(Base64URL.encode(sha256.digest(cert.getEncoded())), rsaKey.getX509CertSHA256Thumbprint());
		assertNull(rsaKey.getAlgorithm());
		assertNull(rsaKey.getKeyOperations());
	}
	
	
	public void testParseFromX509CertWithECPublicKey()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		try {
			RSAKey.parse(cert);
			fail();
		} catch (JOSEException e) {
			assertEquals("The public key of the X.509 certificate is not RSA", e.getMessage());
		}
	}
	
	
	public void testX509CertificateChain()
		throws Exception {
		
		List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();
		Base64URL n = Base64URL.encode(rsaPublicKey.getModulus());
		Base64URL e = Base64URL.encode(rsaPublicKey.getPublicExponent());
		
		RSAKey jwk = new RSAKey.Builder(n, e)
			.x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
			.build();
		
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(0), jwk.getX509CertChain().get(0));
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(1), jwk.getX509CertChain().get(1));
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(2), jwk.getX509CertChain().get(2));
		
		String json = jwk.toJSONString();
		
		jwk = RSAKey.parse(json);
		
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(0), jwk.getX509CertChain().get(0));
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(1), jwk.getX509CertChain().get(1));
		assertEquals(SampleCertificates.SAMPLE_X5C_RSA.get(2), jwk.getX509CertChain().get(2));
	}
	
	
	public void testX509CertificateChain_algDoesntMatch() {
		try {
			new RSAKey.Builder(
				new Base64URL(n),
				new Base64URL(e)
			)
			.x509CertChain(SampleCertificates.SAMPLE_X5C_EC)
			.build();
		} catch (IllegalStateException e) {
			assertEquals("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters", e.getMessage());
		}
	}
	
	
	public void testX509CertificateChain_modulusDoesntMatch()
		throws Exception {
		
		List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();
		
		try {
			new RSAKey.Builder(
				new Base64URL(n), // other mod
				Base64URL.encode(rsaPublicKey.getPublicExponent())
			)
			.x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
			.build();
		} catch (IllegalStateException e) {
			assertEquals("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters", e.getMessage());
		}
	}
	
	
	public void testX509CertificateChain_exponentDoesntMatch()
		throws Exception {
		
		List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey) chain.get(0).getPublicKey();
		
		try {
			new RSAKey.Builder(
				Base64URL.encode(rsaPublicKey.getModulus()),
				new Base64URL("AAAA") // other exp
			)
			.x509CertChain(SampleCertificates.SAMPLE_X5C_RSA)
			.build();
		} catch (IllegalStateException e) {
			assertEquals("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters", e.getMessage());
		}
	}
	
	
	public void testLoadFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		// Generate certificate
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new Certificate[]{cert});
		
		// Load
		RSAKey rsaKey = RSAKey.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(rsaKey);
		assertEquals(KeyUse.SIGNATURE, rsaKey.getKeyUse());
		assertEquals("1", rsaKey.getKeyID());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertNotNull(rsaKey.getX509CertSHA256Thumbprint());
		assertTrue(rsaKey.isPrivate());
		assertEquals(keyStore, rsaKey.getKeyStore());
		
		// Try to load with bad pin
		try {
			RSAKey.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't retrieve private RSA key (bad pin?): Cannot recover key", e.getMessage());
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadFromKeyStore_publicKeyOnly()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		keyStore.setCertificateEntry("1", cert);
		
		RSAKey rsaKey = RSAKey.load(keyStore, "1", null);
		assertNotNull(rsaKey);
		assertEquals(KeyUse.ENCRYPTION, rsaKey.getKeyUse());
		assertEquals("1", rsaKey.getKeyID());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertEquals(1, rsaKey.getParsedX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertNotNull(rsaKey.getX509CertSHA256Thumbprint());
		assertFalse(rsaKey.isPrivate());
		assertEquals(keyStore, rsaKey.getKeyStore());
	}
	
	
	public void testLoadFromKeyStore_notRSA()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		
		keyStore.setCertificateEntry("1", cert);
		
		try {
			RSAKey.load(keyStore, "1", null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Couldn't load RSA JWK: The key algorithm is not RSA", e.getMessage());
		}
	}
	
	
	public void testLoadFromKeyStore_notFound()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		assertNull(RSAKey.load(keyStore, "1", null));
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/274/compile-error-when-using-any-of-the
	public void testGenerator_fromOutsidePackage()
		throws JOSEException {
		
		RSAKey senderJWK = new RSAKeyGenerator(2048)
			.keyID("123")
			.keyUse(KeyUse.SIGNATURE)
			.generate();
		
		assertEquals(2048, senderJWK.size());
		assertEquals("123", senderJWK.getKeyID());
		assertEquals(KeyUse.SIGNATURE, senderJWK.getKeyUse());
	}

	
	public void testEqualsSuccess()
			throws Exception {

		//Given
		String json = "{   \"kty\" : \"RSA\",\n" +
				"   \"n\"   : \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\n" +
				"            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\n" +
				"            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\n" +
				"            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\n" +
				"            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\n" +
				"            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
				"   \"e\"   : \"AQAB\",\n" +
				"   \"d\"   : \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\n" +
				"            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\n" +
				"            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\n" +
				"            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\n" +
				"            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\n" +
				"            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\n" +
				"   \"p\"   : \"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\n" +
				"            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\n" +
				"            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\n" +
				"   \"q\"   : \"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\n" +
				"            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\n" +
				"            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\n" +
				"   \"dp\"  : \"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\n" +
				"            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\n" +
				"            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\n" +
				"   \"dq\"  : \"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\n" +
				"            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\n" +
				"            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\n" +
				"   \"qi\"  : \"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\n" +
				"            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\n" +
				"            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\n" +
				"   \"alg\" : \"RS256\",\n" +
				"   \"kid\" : \"2011-04-29\"\n" +
				" }";
		RSAKey keyA = RSAKey.parse(json.replaceAll("\n", ""));
		RSAKey keyB = RSAKey.parse(json.replaceAll("\n", ""));

		//When

		//Then
		assertEquals(keyA, keyB);
	}

	
	public void testEqualsFailure()
			throws Exception {

		//Given
		String jsonA = "{   \"kty\" : \"RSA\",\n" +
				"   \"n\"   : \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx\n" +
				"            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs\n" +
				"            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2\n" +
				"            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI\n" +
				"            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb\n" +
				"            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
				"   \"e\"   : \"AQAB\",\n" +
				"   \"d\"   : \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\n" +
				"            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\n" +
				"            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\n" +
				"            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\n" +
				"            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\n" +
				"            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\n" +
				"   \"p\"   : \"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\n" +
				"            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\n" +
				"            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\n" +
				"   \"q\"   : \"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\n" +
				"            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\n" +
				"            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\n" +
				"   \"dp\"  : \"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\n" +
				"            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\n" +
				"            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\n" +
				"   \"dq\"  : \"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\n" +
				"            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\n" +
				"            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\n" +
				"   \"qi\"  : \"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\n" +
				"            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\n" +
				"            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\n" +
				"   \"alg\" : \"RS256\",\n" +
				"   \"kid\" : \"2011-04-29\"\n" +
				" }";
		RSAKey keyA = RSAKey.parse(jsonA.replaceAll("\n", ""));

		String jsonB = "{\n" +
				"      \"kty\": \"RSA\",\n" +
				"      \"d\": \"Y03dVLbCCgWpiZnzUyT1E_JuQkM9-Kl9ice2Yp_8ex-ywZHF1GvYYBsKyKjAf3o_dua5XX9IDILK2TJZ2uhWefaEPMhh1OL4rveEoq4-jU3kdax-_8WJ8r-gatoUXl-IyDePiMZGgd4uTLzqF752-qtPEBmbfQK7ndP1z6h5t2fUA-h_Z6DIXuguci-2I_mDu9QA4tRUdwClDRVY8J6tNj8YhZiz6xdtCkbDeonDTvOGmmDJNStkp4WVzpE_D09cudLMAz8_g2_y6j_Jq6EGhrVLP85JEfJI3YBpGGgOdQMRIqm0xp8xjY9Pz5bIc3yCbpWV2FeJyk3eKXtQCpSPgQ\",\n" +
				"      \"e\": \"AQAB\",\n" +
				"      \"n\": \"w1-xUupu_rLsGPUaFYk0ZYhMNhWQ-scT4DlNPvuPDV2ocfWe1Jl2kuOz0o_UKmmSCMsTDZ2IzT79gJL2qCcNGwFsXOcgvaUYxM2HUF7QP6rM9afLhyHR99m4t1sptfXlLUqNPYC2iexH_HVzabaokyRfKxiFKFs-L1Jns1HddkkWbATCnRAEMOMAqtFRLNwpX4qtEfENie7DCMZE6Sjz-grz4Z1f7-AzIvW3EzNOpxYZcLONfFC0iyLHIadcMln73pb7iXUKGLdvFcmtEmSoF6KfrC1SM_s_02NtaIFXzKhVG4c-1iBijhTprPC3Q4Q6cEKLROAyGnrsAg6ByzlsNQ\",\n" +
				"      \"alg\" : \"RS256\",\n" +
				"      \"kid\" : \"2011-04-29\"\n" +
				"    }";
		RSAKey keyB = RSAKey.parse(jsonB.replaceAll("\n", ""));

		//When

		//Then
		assertNotEquals(keyA, keyB);
	}
	
	
	public void testRSAKeyRoundtripWithX5c() throws Exception {
		
		RSAKey rsaKey = RSAKey.parse(
			"{\"kty\":\"RSA\",\"x5t#S256\":\"QOjjUwPhfMBMIT2zn5nrUxc4GocujsSHziKh-FlvmiU\",\"e\":\"AQAB\",\"kid\":\"18031265869169735523\",\"x5c\":[\"MIIDljCCAn4CCQD6O+zGNny3YzANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMCQkUxEDAOBgNVBAgTB0JlbGdpdW0xETAPBgNVBAcTCEJydXNzZWxzMRwwGgYDVQQKExNFdXJvcGVhbiBDb21taXNzaW9uMRAwDgYDVQQLEwdTRkMyMDE0MR8wHQYDVQQDExZTRkMyMDE0IENBIERFVkVMT1BNRU5UMSAwHgYJKoZIhvcNAQkBFhF2YW53b2JlQHlhaG9vLkNvbTAeFw0xNjEwMTgxNTE4NTdaFw0yNjEwMTYxNTE4NTdaMHQxCzAJBgNVBAYTAkJFMRAwDgYDVQQIEwdCRUxHSVVNMREwDwYDVQQHEwhCcnVzc2VsczEcMBoGA1UEChMTRXVyb3BlYW4gQ29tbWlzc2lvbjEQMA4GA1UECxMHU0ZDMjAxNDEQMA4GA1UEAxMHdmFud29iZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMC7n95a0Yp\\/anE2ya3VhUjJ8KhoC8mAiblGJYMPsB2QfLKJEoZ2eSCD\\/GwkxufEb8UPauQDFogMshUZwwZ08k0OXywh3a9xO9zI+CCz23TNvueACQzWbtwWrx6lU5ljOOhBdt+c\\/CRXXgG2kH+hhs8MaV5KgN6iPf0HilH3QP2pwLNVLrupm\\/0r9CwuEc\\/wWLbi1nLno366vn\\/+jdsuxSrWnr\\/S8SCY3+L6CzZfhWMzF1SrsiCn+v6MirAwcG2IckNomGiL+X7PjObOSIWDVa7G9\\/Ouh4EaZN0w\\/zUvMSZ8mXkTo\\/Qk48kQlzm\\/KoQpEcoa9Dng4EdGyXzsipxsCNsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAlBtx8Lh3PL1PBoiki5VkPUqfNlYNE6C+3faPzjEKu0D8+g\\/y1AbFp7442J3QqX0yfS\\/qG3BIc2dU8ICDhmstn7d2yr+FDFF4raQ8OfMocQy66Rf6wgAQy0YETWF+gBx8bKhd3D+V12paZg8ocDE7+V0UOCmxRMSz8hRvycCYGlf5pD2v2DIfPatNgwyASZK+qu+w++OrilC3wXKG2XD8AWaoTWMWz1ycov6pSnRGEr0DNxF4DBWrJWe\\/b+HH1K1hiKG0lnD520Ldoy3VRF86uRBnAjKX0yy7LHZy1QaB6M5DHtzOQFg7GldjhuZVFA01smyadepiOI0jc6jTwghT2Q==\"],\"n\":\"wLuf3lrRin9qcTbJrdWFSMnwqGgLyYCJuUYlgw-wHZB8sokShnZ5IIP8bCTG58RvxQ9q5AMWiAyyFRnDBnTyTQ5fLCHdr3E73Mj4ILPbdM2-54AJDNZu3BavHqVTmWM46EF235z8JFdeAbaQf6GGzwxpXkqA3qI9_QeKUfdA_anAs1Uuu6mb_Sv0LC4Rz_BYtuLWcuejfrq-f_6N2y7FKtaev9LxIJjf4voLNl-FYzMXVKuyIKf6_oyKsDBwbYhyQ2iYaIv5fs-M5s5IhYNVrsb3866HgRpk3TD_NS8xJnyZeROj9CTjyRCXOb8qhCkRyhr0OeDgR0bJfOyKnGwI2w\"}");
		
		JSONObject jsonObject = rsaKey.toJSONObject();
		JSONArray x5cArray = (JSONArray) jsonObject.get("x5c");
		assertEquals(rsaKey.getX509CertChain().get(0).toString(), x5cArray.get(0));
		assertEquals(1, x5cArray.size());
		
		// Fails with java.text.ParseException: Unexpected type of JSON object member with key "x5c"
		RSAKey secondPassKey = RSAKey.parse(rsaKey.toJSONObject());
		
		assertEquals(secondPassKey, rsaKey);
	}
}
