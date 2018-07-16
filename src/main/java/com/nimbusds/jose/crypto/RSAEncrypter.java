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


import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. Expects a
 * public RSA key.
 *
 * <p>Encrypts the plain text with a generated AES key (the Content Encryption
 * Key) according to the specified JOSE encryption method, then encrypts the
 * CEK with the public RSA key and returns it alongside the IV, cipher text and
 * authentication tag. See RFC 7518, sections
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.2">4.2</a> and
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.3">4.3</a> for more
 * information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP} (deprecated)
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5} (deprecated)
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version 2015-06-08
 */
@ThreadSafe
public class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;

	/**
	 * The content encryption key. Must be an AES key
	 */
	private final SecretKey contentEncryptionKey;

	/**
	 * Creates a new RSA encrypter.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 */
	public RSAEncrypter(final RSAPublicKey publicKey) {

		this(publicKey, null);;
	}


	/**
	 * Creates a new RSA encrypter.
	 *
	 *  @param rsaJWK The RSA JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the RSA JWK extraction failed.
	 */
	public RSAEncrypter(final RSAKey rsaJWK)
		throws JOSEException {

		this(rsaJWK.toRSAPublicKey());
	}


	/**
	 * Gets the public RSA key.
	 *
	 * @return The public RSA key.
	 */
	public RSAPublicKey getPublicKey() {

		return publicKey;
	}


	/**
	 * Creates a new RSA encrypter with specified content encryption key.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 * @param contentEncryptionKey The content encryption key. Its algorithm must be "AES"
	 */
	public RSAEncrypter(final RSAPublicKey publicKey, final SecretKey contentEncryptionKey) {
		if (publicKey == null) {
			throw new IllegalArgumentException("The public RSA key must not be null");
		}
		this.publicKey = publicKey;

		if (contentEncryptionKey != null) {
			if (contentEncryptionKey.getAlgorithm() == null || !contentEncryptionKey.getAlgorithm().equals("AES")) {
				throw new IllegalArgumentException("The content encryption key must be an AES key");
			} else {
				this.contentEncryptionKey = contentEncryptionKey;
			}
		} else {
			this.contentEncryptionKey = null;
		}
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final EncryptionMethod enc = header.getEncryptionMethod();

		// Generate and encrypt the CEK according to the enc method
		SecretKey cek = contentEncryptionKey;
		if (cek == null) {
			// Generate and encrypt the CEK according to the enc method
			cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());
		}

		final Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.RSA1_5)) {

			encryptedKey = Base64URL.encode(RSA1_5.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP)) {

			encryptedKey = Base64URL.encode(RSA_OAEP.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));

		} else if (alg.equals(JWEAlgorithm.RSA_OAEP_256)) {
			
			encryptedKey = Base64URL.encode(RSA_OAEP_256.encryptCEK(publicKey, cek, getJCAContext().getKeyEncryptionProvider()));
			
		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey, getJCAContext());
	}
}