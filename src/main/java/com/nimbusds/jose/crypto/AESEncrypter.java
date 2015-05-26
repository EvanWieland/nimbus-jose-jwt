package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * AES encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256GCMKW}
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
 * @author Melisa Halsband
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-20)
 */
@ThreadSafe
public class AESEncrypter extends AESCryptoProvider implements JWEEncrypter {


	/**
	 * Algorithm family constants.
	 */
	private enum AlgFamily {

		AESKW, AESGCMKW
	}


	/**
	 * Creates a new AES encrypter.
	 *
	 * @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192
	 *            bits (24 bytes) or 256 bits (32 bytes). Must not be
	 *            {@code null}.
	 */
	public AESEncrypter(final SecretKey kek) {

		super(kek);
	}

	/**
	 * Creates a new AES encrypter.
	 *
	 * @param keyBytes The Key Encryption Key, as a byte array. Must be 128
	 *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
	 *                 bytes). Must not be {@code null}.
	 */
	public AESEncrypter(final byte[] keyBytes) {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Creates a new AES encrypter.
	 *
	 * @param octJWK The Key Encryption Key, as a JWK. Must be 128 bits (16
	 *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
	 *               be {@code null}.
	 */
	public AESEncrypter(final OctetSequenceKey octJWK) {

		this(octJWK.toSecretKey("AES"));
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();

		// Check the AES key size and determine the algorithm family
		final AlgFamily algFamily;

		if (alg.equals(JWEAlgorithm.A128KW)) {

			if(getKey().getEncoded().length != 16){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 128 bits for A128KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A192KW)) {

			if(getKey().getEncoded().length != 24){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 192 bits for A192KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A256KW)) {

			if (getKey().getEncoded().length != 32) {
				throw new JOSEException("The Key Encryption Key (KEK) length must be 256 bits for A256KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A128GCMKW)) {

			if(getKey().getEncoded().length != 16){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 128 bits for A128GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else if (alg.equals(JWEAlgorithm.A192GCMKW)) {

			if(getKey().getEncoded().length != 24){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 192 bits for A192GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else if (alg.equals(JWEAlgorithm.A256GCMKW)) {

			if(getKey().getEncoded().length != 32){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 256 bits for A256GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}


		final JWEHeader updatedHeader; // We need to work on the header
		final Base64URL encryptedKey; // The second JWE part

		// Generate and encrypt the CEK according to the enc method
		final EncryptionMethod enc = header.getEncryptionMethod();
		final SecretKey cek = AES.generateKey(enc.cekBitLength(), getJWEJCAProvider().getSecureRandom());

		if(AlgFamily.AESKW.equals(algFamily)) {

			encryptedKey = Base64URL.encode(AESKW.encryptCEK(cek, getKey()));
			updatedHeader = header; // simply copy ref

		} else if(AlgFamily.AESGCMKW.equals(algFamily)) {

			final byte[] keyIV = AESGCM.generateIV(getJWEJCAProvider().getSecureRandom());
			final AuthenticatedCipherText authCiphCEK = AESGCMKW.encryptCEK(cek, keyIV, getKey(), getJWEJCAProvider().getKeyEncryptionProvider());
			encryptedKey = Base64URL.encode(authCiphCEK.getCipherText());

			// Add iv and tag to the header
			updatedHeader = new JWEHeader.Builder(header).
				iv(Base64URL.encode(keyIV)).
				authTag(Base64URL.encode(authCiphCEK.getAuthenticationTag())).
				build();
		} else {
			// This should never happen
			throw new JOSEException("Unexpected JWE algorithm: " + alg);
		}

		return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJWEJCAProvider());
	}
}
