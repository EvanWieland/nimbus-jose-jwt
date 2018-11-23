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

package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.HashSet;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests direct JWE encryption and decryption.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-01-11
 */
public class DirectCryptoTest extends TestCase {


	// 128-bit shared symmetric key
	private final static byte[] key128 = { 
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121, 
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226 };

	// 192-bit shared symmetric key
	private final static byte[] key192 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61 };


	// 256-bit shared symmetric key
	private final static byte[] key256 = { 
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121, 
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61, 
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234 };


	// 384-bit shared symmetric key
	private final static byte[] key384 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61,
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234,
		(byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224,
		(byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127 };


	// 512-bit shared symmetric key
	private final static byte[] key512 = { 
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121, 
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61, 
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234,
		(byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224, 
		(byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127, 
		(byte)121, (byte) 25, (byte)  4, (byte) 85, (byte)220, (byte)144, (byte)215, (byte)110, 
		(byte)130, (byte) 17, (byte) 68, (byte)228, (byte)129, (byte)138, (byte)  7, (byte)130 };



	public void testKeyLengths() {

		assertEquals(128, ByteUtils.bitLength(key128));
		assertEquals(192, ByteUtils.bitLength(key192));
		assertEquals(256, ByteUtils.bitLength(key256));
		assertEquals(384, ByteUtils.bitLength(key384));
		assertEquals(512, ByteUtils.bitLength(key512));
	}


	public void testClassAlgorithmSupport()
		throws Exception {

		assertEquals(1, DirectEncrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(DirectEncrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.DIR));

		assertEquals(1, DirectDecrypter.SUPPORTED_ALGORITHMS.size());
		assertTrue(DirectDecrypter.SUPPORTED_ALGORITHMS.contains(JWEAlgorithm.DIR));
	}


	public void testClassEncryptionMethodSupport()
		throws Exception {

		assertEquals(8, DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		assertEquals(8, DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.size());
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
	}


	public void testInstanceAlgorithmSupport()
		throws Exception {

		JWEEncrypter encrypter = new DirectEncrypter(key128);

		assertEquals(1, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.DIR));

		JWEDecrypter decrypter = new DirectDecrypter(key128);

		assertEquals(1, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.DIR));
	}


	public void testInstanceEncryptionMethodSupport()
		throws Exception {

		// 128-bit key
		JWEEncrypter encrypter = new DirectEncrypter(key128);

		assertEquals(1, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));

		JWEDecrypter decrypter = new DirectDecrypter(key128);

		assertEquals(1, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));

		// 192-bit key
		encrypter = new DirectEncrypter(key192);

		assertEquals(1, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));

		decrypter = new DirectDecrypter(key192);

		assertEquals(1, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));

		// 256-bit key
		encrypter = new DirectEncrypter(key256);

		assertEquals(3, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));

		decrypter = new DirectDecrypter(key256);

		assertEquals(3, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));

		// 384-bit key
		encrypter = new DirectEncrypter(key384);

		assertEquals(1, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));

		decrypter = new DirectDecrypter(key384);

		assertEquals(1, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));

		// 512-bit key
		encrypter = new DirectEncrypter(key512);

		assertEquals(2, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		decrypter = new DirectDecrypter(key512);

		assertEquals(2, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
	}


	public void testWithA128CBC_HS256()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new DirectEncrypter(key256);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new DirectDecrypter(key256);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new DirectEncrypter(key384);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new DirectDecrypter(key384);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new DirectEncrypter(key512);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new DirectDecrypter(key512);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		DirectEncrypter encrypter = new DirectEncrypter(key128);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		DirectDecrypter decrypter = new DirectDecrypter(key128);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		DirectEncrypter encrypter = new DirectEncrypter(key192);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		DirectDecrypter decrypter = new DirectDecrypter(key192);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		DirectEncrypter encrypter = new DirectEncrypter(key256);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		DirectDecrypter decrypter = new DirectDecrypter(key256);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}


	public void testOctJWKConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);

		JWEObject jweObject = new JWEObject(header, new Payload("I think therefore I am."));

		OctetSequenceKey oct = new OctetSequenceKey.Builder(key256).build();

		DirectEncrypter encrypter = new DirectEncrypter(oct);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.encrypt(encrypter);

		jweObject = JWEObject.parse(jweObject.serialize());

		DirectDecrypter decrypter = new DirectDecrypter(oct);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals("I think therefore I am.", jweObject.getPayload().toString());
	}


	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new DirectEncrypter(key256);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new DirectDecrypter(key256);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCookbookExample()
		throws Exception {

		// Frpm http://tools.ietf.org/html/rfc7520#section-5.6

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\","+
			"\"use\":\"enc\","+
			"\"alg\":\"A128GCM\","+
			"\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);


		String jwe = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT"+
			"diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0"+
			"."+
			"."+
			"refa467QzzKx6QAB"+
			"."+
			"JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y"+
			"hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM"+
			"DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_"+
			"BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5"+
			"g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn"+
			"ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp"+
			"."+
			"vbb32Xvllea2OtmHAdccRQ";

		JWEObject jweObject = JWEObject.parse(jwe);

		assertEquals(JWEAlgorithm.DIR, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, jweObject.getHeader().getEncryptionMethod());
		assertEquals("77c7e2b8-6e13-45cf-8672-617b5b45243a", jweObject.getHeader().getKeyID());

		DirectDecrypter decrypter = new DirectDecrypter(jwk.toByteArray());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

		jweObject.decrypt(decrypter);

		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new DirectEncrypter(key256);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new DirectDecrypter(new SecretKeySpec(key256, "AES"), new HashSet<>(Collections.singletonList("exp")));

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new DirectEncrypter(key256);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new DirectDecrypter(key256);

		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}
	
	
	public void testKeyLengthMismatch()
		throws Exception {
		
		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
		JWEObject jweObject = new JWEObject(header, new Payload("Hello, world!"));
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		int keyBitLength = EncryptionMethod.A128CBC_HS256.cekBitLength() / 2; // too short
		keyGen.init(keyBitLength);
		SecretKey key = keyGen.generateKey();

		try {
			jweObject.encrypt(new DirectEncrypter(key));
			fail();
		} catch (JOSEException e) {
			
			assertEquals("The \"A128CBC-HS256\" encryption method or key size is not supported by the JWE encrypter: Supported methods: [A128GCM]", e.getMessage());
		}
	}
	
	
	public void testAcceptAnySecretKeyAlg()
		throws Exception {
		
		String plainText = "Hello, world!";
		
		// 128 bit
		SecretKey secretKey = new SecretKeySpec(key128, "NONE");
		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new Payload(plainText));
		jweObject.encrypt(new DirectEncrypter(secretKey));
		jweObject = JWEObject.parse(jweObject.serialize());
		jweObject.decrypt(new DirectDecrypter(secretKey));
		assertEquals(plainText, jweObject.getPayload().toString());
		
		// 192 bit
		secretKey = new SecretKeySpec(key192, "NONE");
		jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192GCM), new Payload(plainText));
		jweObject.encrypt(new DirectEncrypter(secretKey));
		jweObject = JWEObject.parse(jweObject.serialize());
		jweObject.decrypt(new DirectDecrypter(secretKey));
		assertEquals(plainText, jweObject.getPayload().toString());
		
		// 256 bit
		secretKey = new SecretKeySpec(key256, "NONE");
		jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), new Payload(plainText));
		jweObject.encrypt(new DirectEncrypter(secretKey));
		jweObject = JWEObject.parse(jweObject.serialize());
		jweObject.decrypt(new DirectDecrypter(secretKey));
		assertEquals(plainText, jweObject.getPayload().toString());
		
		secretKey = new SecretKeySpec(key256, "NONE");
		jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload(plainText));
		jweObject.encrypt(new DirectEncrypter(secretKey));
		jweObject = JWEObject.parse(jweObject.serialize());
		jweObject.decrypt(new DirectDecrypter(secretKey));
		assertEquals(plainText, jweObject.getPayload().toString());
	}
}
