/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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


import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.ListIterator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;


/**
 * Default processor of {@link com.nimbusds.jwt.PlainJWT unsecured} (plain),
 * {@link com.nimbusds.jwt.SignedJWT signed} and
 * {@link com.nimbusds.jwt.EncryptedJWT encrypted} JSON Web Tokens (JWTs).
 *
 * <p>Must be configured with the following:
 *
 * <ul>
 *     <li>To process signed JWTs: A {@link #setJWSKeySelector JWS key
 *     selector} using the header or the {@link JWTClaimsSetAwareJWSKeySelector
 *     header and claims set} to suggest key candidate(s) for the signature
 *     verification. The key selection procedure is application-specific and
 *     may involve key ID lookup, a certificate check and / or some
 *     {@link SecurityContext context}.</li>
 *
 *     <li>To process encrypted JWTs: A {@link #setJWEKeySelector JWE key
 *     selector} using the header to suggest key candidate(s) for decryption.
 *     The key selection procedure is application-specific and may involve key
 *     ID lookup, a certificate check and / or some {@link SecurityContext
 *     context}.</li>
 * </ul>
 *
 * <p>An optional {@link SecurityContext context} parameter is available to
 * facilitate passing of additional data between the caller and the underlying
 * selector of key candidates (in both directions).
 *
 * <p>See sections 6 of RFC 7515 (JWS) and RFC 7516 (JWE) for guidelines on key
 * selection.
 *
 * <p>This processor is configured with a standard header "typ" (type)
 * parameter {@link DefaultJOSEObjectTypeVerifier#JWT verifier} which expects
 * the signed, encrypted and plain (unsecured) JWTs to have the type header
 * omitted or set to {@link JOSEObjectType#JWT JWT}. To accept other "typ"
 * values pass an appropriately configured JWS and / or JWE
 * {@link DefaultJOSEObjectTypeVerifier type verifier}.
 *
 * <p>This processor comes with the default {@link DefaultJWSVerifierFactory
 * JWS verifier factory} and the default {@link DefaultJWEDecrypterFactory
 * JWE decrypter factory}; they can construct verifiers / decrypters for all
 * standard JOSE algorithms implemented by the library.
 *
 * <p>Note that for security reasons this processor is hardwired to reject
 * unsecured (plain) JWTs. Override the {@link #process(PlainJWT, SecurityContext)}
 * if you need to handle plain JWTs.
 *
 * <p>A {@link DefaultJWTClaimsVerifier default JWT claims verifier} is
 * provided, to perform a minimal check of the claims after a successful JWS
 * verification / JWE decryption. It checks the token expiration (exp) and
 * not-before (nbf) timestamps if these are present. The default JWT claims
 * verifier may be extended to perform additional checks, such as issuer and
 * subject acceptance.
 *
 * <p>To process generic JOSE objects (with arbitrary payloads) use the
 * {@link com.nimbusds.jose.proc.DefaultJOSEProcessor} class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-15
 */
public class DefaultJWTProcessor<C extends SecurityContext> implements ConfigurableJWTProcessor<C> {

	
	/**
	 * The JWS type verifier.
	 */
	private JOSEObjectTypeVerifier<C> jwsTypeVerifier = DefaultJOSEObjectTypeVerifier.JWT;
	
	
	/**
	 * The JWE type verifier.
	 */
	private JOSEObjectTypeVerifier<C> jweTypeVerifier = DefaultJOSEObjectTypeVerifier.JWT;
	

	/**
	 * The JWS key selector.
	 */
	private JWSKeySelector<C> jwsKeySelector;
	
	
	/**
	 * The JWT claims aware JWS key selector, alternative to
	 * {@link #jwsKeySelector}.
	 */
	private JWTClaimsSetAwareJWSKeySelector<C> claimsSetAwareJWSKeySelector;


	/**
	 * The JWE key selector.
	 */
	private JWEKeySelector<C> jweKeySelector;


	/**
	 * The JWS verifier factory.
	 */
	private JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();


	/**
	 * The JWE decrypter factory.
	 */
	private JWEDecrypterFactory jweDecrypterFactory = new DefaultJWEDecrypterFactory();


	/**
	 * The claims verifier.
	 */
	private JWTClaimsSetVerifier<C> claimsVerifier = new DefaultJWTClaimsVerifier<>();
	
	
	/**
	 * The deprecated claims verifier.
	 */
	private JWTClaimsVerifier deprecatedClaimsVerifier = null;
	
	
	@Override
	public JOSEObjectTypeVerifier<C> getJWSTypeVerifier() {
		
		return jwsTypeVerifier;
	}
	
	
	@Override
	public void setJWSTypeVerifier(final JOSEObjectTypeVerifier<C> jwsTypeVerifier) {
	
		this.jwsTypeVerifier = jwsTypeVerifier;
	}
	
	
	@Override
	public JWSKeySelector<C> getJWSKeySelector() {

		return jwsKeySelector;
	}


	@Override
	public void setJWSKeySelector(final JWSKeySelector<C> jwsKeySelector) {

		this.jwsKeySelector = jwsKeySelector;
	}
	
	
	@Override
	public JWTClaimsSetAwareJWSKeySelector<C> getJWTClaimsSetAwareJWSKeySelector() {
		
		return claimsSetAwareJWSKeySelector;
	}
	
	
	@Override
	public void setJWTClaimsSetAwareJWSKeySelector(final JWTClaimsSetAwareJWSKeySelector<C> jwsKeySelector) {
	
		this.claimsSetAwareJWSKeySelector = jwsKeySelector;
	}
	
	
	@Override
	public JOSEObjectTypeVerifier<C> getJWETypeVerifier() {
		
		return jweTypeVerifier;
	}
	
	
	@Override
	public void setJWETypeVerifier(final JOSEObjectTypeVerifier<C> jweTypeVerifier) {
		
		this.jweTypeVerifier = jweTypeVerifier;
	}
	
	
	@Override
	public JWEKeySelector<C> getJWEKeySelector() {

		return jweKeySelector;
	}


	@Override
	public void setJWEKeySelector(final JWEKeySelector<C> jweKeySelector) {

		this.jweKeySelector = jweKeySelector;
	}


	@Override
	public JWSVerifierFactory getJWSVerifierFactory() {

		return jwsVerifierFactory;
	}


	@Override
	public void setJWSVerifierFactory(final JWSVerifierFactory factory) {

		jwsVerifierFactory = factory;
	}


	@Override
	public JWEDecrypterFactory getJWEDecrypterFactory() {

		return jweDecrypterFactory;
	}


	@Override
	public void setJWEDecrypterFactory(final JWEDecrypterFactory factory) {

		jweDecrypterFactory = factory;
	}
	
	
	@Override
	public JWTClaimsSetVerifier<C> getJWTClaimsSetVerifier() {
		
		return claimsVerifier;
	}
	
	
	@Override
	public void setJWTClaimsSetVerifier(final JWTClaimsSetVerifier<C> claimsVerifier) {
		
		this.claimsVerifier = claimsVerifier;
		this.deprecatedClaimsVerifier = null; // clear other verifier
	}
	
	
	@Override
	@Deprecated
	public JWTClaimsVerifier getJWTClaimsVerifier() {

		return deprecatedClaimsVerifier;
	}


	@Override
	@Deprecated
	public void setJWTClaimsVerifier(final JWTClaimsVerifier claimsVerifier) {

		this.claimsVerifier = null; // clear official verifier
		this.deprecatedClaimsVerifier = claimsVerifier;
	}
	
	
	private JWTClaimsSet extractJWTClaimsSet(final JWT jwt)
		throws BadJWTException {
		
		try {
			return jwt.getJWTClaimsSet();
		} catch (ParseException e) {
			// Payload not a JSON object
			throw new BadJWTException(e.getMessage(), e);
		}
	}


	private JWTClaimsSet verifyClaims(final JWTClaimsSet claimsSet, final C context)
		throws BadJWTException {
		
		if (getJWTClaimsSetVerifier() != null) {
			getJWTClaimsSetVerifier().verify(claimsSet, context);
		} else if (getJWTClaimsVerifier() != null) {
			// Fall back to deprecated claims verifier
			getJWTClaimsVerifier().verify(claimsSet);
		}
		return claimsSet;
	}
	
	
	private List<? extends Key> selectKeys(final JWSHeader header, final JWTClaimsSet claimsSet, final C context)
		throws KeySourceException, BadJOSEException {
		
		if (getJWTClaimsSetAwareJWSKeySelector() != null) {
			return getJWTClaimsSetAwareJWSKeySelector().selectKeys(header, claimsSet, context);
		} else if (getJWSKeySelector() != null) {
			return getJWSKeySelector().selectJWSKeys(header, context);
		} else {
			throw new BadJOSEException("Signed JWT rejected: No JWS key selector is configured");
		}
	}


	@Override
	public JWTClaimsSet process(final String jwtString, final C context)
		throws ParseException, BadJOSEException, JOSEException {

		return process(JWTParser.parse(jwtString), context);
	}


	@Override
	public JWTClaimsSet process(final JWT jwt, final C context)
		throws BadJOSEException, JOSEException {

		if (jwt instanceof SignedJWT) {
			return process((SignedJWT)jwt, context);
		}

		if (jwt instanceof EncryptedJWT) {
			return process((EncryptedJWT)jwt, context);
		}

		if (jwt instanceof PlainJWT) {
			return process((PlainJWT)jwt, context);
		}

		// Should never happen
		throw new JOSEException("Unexpected JWT object type: " + jwt.getClass());
	}


	@Override
	public JWTClaimsSet process(final PlainJWT plainJWT, final C context)
		throws BadJOSEException, JOSEException {
		
		// JWS type verifier applies to unsecured JOSE as well
		if (jwsTypeVerifier == null) {
			throw new BadJOSEException("Plain JWT rejected: No JWS header \"typ\" (type) verifier is configured");
		}
		jwsTypeVerifier.verify(plainJWT.getHeader().getType(), context);
		
		throw new BadJOSEException("Unsecured (plain) JWTs are rejected, extend class to handle");
	}


	@Override
	public JWTClaimsSet process(final SignedJWT signedJWT, final C context)
		throws BadJOSEException, JOSEException {
		
		if (jwsTypeVerifier == null) {
			throw new BadJOSEException("Signed JWT rejected: No JWS header \"typ\" (type) verifier is configured");
		}
		
		jwsTypeVerifier.verify(signedJWT.getHeader().getType(), context);

		if (getJWSKeySelector() == null && getJWTClaimsSetAwareJWSKeySelector() == null) {
			// JWS key selector may have been deliberately omitted
			throw new BadJOSEException("Signed JWT rejected: No JWS key selector is configured");
		}

		if (getJWSVerifierFactory() == null) {
			throw new JOSEException("No JWS verifier is configured");
		}
		
		JWTClaimsSet claimsSet = extractJWTClaimsSet(signedJWT);

		List<? extends Key> keyCandidates = selectKeys(signedJWT.getHeader(), claimsSet, context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("Signed JWT rejected: Another algorithm expected, or no matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWSVerifier verifier = getJWSVerifierFactory().createJWSVerifier(signedJWT.getHeader(), it.next());

			if (verifier == null) {
				continue;
			}

			final boolean validSignature = signedJWT.verify(verifier);

			if (validSignature) {
				return verifyClaims(claimsSet, context);
			}

			if (! it.hasNext()) {
				// No more keys to try out
				throw new BadJWSException("Signed JWT rejected: Invalid signature");
			}
		}

		throw new BadJOSEException("JWS object rejected: No matching verifier(s) found");
	}


	@Override
	public JWTClaimsSet process(final EncryptedJWT encryptedJWT, final C context)
		throws BadJOSEException, JOSEException {
		
		if (jweTypeVerifier == null) {
			throw new BadJOSEException("Encrypted JWT rejected: No JWE header \"typ\" (type) verifier is configured");
		}
		
		jweTypeVerifier.verify(encryptedJWT.getHeader().getType(), context);

		if (getJWEKeySelector() == null) {
			// JWE key selector may have been deliberately omitted
			throw new BadJOSEException("Encrypted JWT rejected: No JWE key selector is configured");
		}

		if (getJWEDecrypterFactory() == null) {
			throw new JOSEException("No JWE decrypter is configured");
		}

		List<? extends Key> keyCandidates = getJWEKeySelector().selectJWEKeys(encryptedJWT.getHeader(), context);

		if (keyCandidates == null || keyCandidates.isEmpty()) {
			throw new BadJOSEException("Encrypted JWT rejected: Another algorithm expected, or no matching key(s) found");
		}

		ListIterator<? extends Key> it = keyCandidates.listIterator();

		while (it.hasNext()) {

			JWEDecrypter decrypter = getJWEDecrypterFactory().createJWEDecrypter(encryptedJWT.getHeader(), it.next());

			if (decrypter == null) {
				continue;
			}

			try {
				encryptedJWT.decrypt(decrypter);

			} catch (JOSEException e) {

				if (it.hasNext()) {
					// Try next key
					continue;
				}

				// No more keys to try
				throw new BadJWEException("Encrypted JWT rejected: " + e.getMessage(), e);
			}

			if ("JWT".equalsIgnoreCase(encryptedJWT.getHeader().getContentType())) {

				// Handle nested signed JWT, see http://tools.ietf.org/html/rfc7519#section-5.2
				SignedJWT signedJWTPayload = encryptedJWT.getPayload().toSignedJWT();

				if (signedJWTPayload == null) {
					// Cannot parse payload to signed JWT
					throw new BadJWTException("The payload is not a nested signed JWT");
				}

				return process(signedJWTPayload, context);
			}

			JWTClaimsSet claimsSet = extractJWTClaimsSet(encryptedJWT);
			return verifyClaims(claimsSet, context);
		}

		throw new BadJOSEException("Encrypted JWT rejected: No matching decrypter(s) found");
	}
}
