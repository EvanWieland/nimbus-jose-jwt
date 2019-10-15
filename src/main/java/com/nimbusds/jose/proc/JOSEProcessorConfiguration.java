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

package com.nimbusds.jose.proc;


/**
 * JOSE processor configuration.
 *
 * <p>Specifies the required components to process secured JOSE objects:
 *
 * <ul>
 *     <li>To verify JWS objects:
 *         <ul>
 *             <li>{@link #setJWSTypeVerifier Verifier} for the acceptable JWS
 *                 header "typ" (type) parameters.
 *             <li>{@link #setJWSKeySelector Key selector} to determine key
 *                 candidate(s) for JWS verification based on the JWS header,
 *                 payload and / or application-specific context information.
 *             <li>{@link #setJWSVerifierFactory Factory} to construct a JWS
 *                 verifier for a given key candidate and JWS header information.
 *         </ul>
 *     <li>To decrypt JWE objects:
 *         <ul>
 *             <li>{@link #setJWETypeVerifier Verifier} for the acceptable JWE
 *                 header "typ" (type) parameters.
 *             <li>{@link #setJWEKeySelector Key selector} to determine key
 *                 candidate(s) for JWE decryption based on the JWE header and
 *                 / or application-specific context information.
 *             <li>{@link #setJWEDecrypterFactory Factory} to construct a JWE
 *                 decrypter for a given key candidate and JWE header
 *                 information.
 *         </ul>
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-15
 */
public interface JOSEProcessorConfiguration <C extends SecurityContext> {
	
	
	/**
	 * Gets the JWS header "typ" (type) parameter verifier. This verifier
	 * is also applied to plain (unsecured) JOSE objects. If none JWS
	 * and plain objects will be rejected.
	 *
	 * @return The JWS type verifier, {@code null} if not specified.
	 *
	 * @since 8.0
	 */
	JOSEObjectTypeVerifier<C> getJWSTypeVerifier();
	
	
	/**
	 * Sets the JWS header "typ" (type) parameter verifier. This verifier
	 * is also applied to plain (unsecured) JOSE objects. If none JWS and
	 * plain objects will be rejected.
	 *
	 * @param jwsTypeVerifier The JWS type verifier, {@code null} if not
	 *                        specified.
	 *
	 * @since 8.0
	 */
	void setJWSTypeVerifier(final JOSEObjectTypeVerifier<C> jwsTypeVerifier);

	
	/**
	 * Gets the JWS key selector. If none JWS objects will be rejected.
	 *
	 * @return The JWS key selector, {@code null} if not specified.
	 */
	JWSKeySelector<C> getJWSKeySelector();


	/**
	 * Sets the JWS key selector. If none JWS objects will be rejected.
	 *
	 * @param jwsKeySelector The JWS key selector, {@code null} if not
	 *                       specified.
	 */
	void setJWSKeySelector(final JWSKeySelector<C> jwsKeySelector);
	
	
	/**
	 * Gets the JWE header "typ" (type) parameter verifier. If none JWE
	 * objects will be rejected.
	 *
	 * @return The JWE verifier, {@code null} if not specified.
	 *
	 * @since 8.0
	 */
	JOSEObjectTypeVerifier<C> getJWETypeVerifier();
	
	
	/**
	 * Sets the JWE header "typ" (type) parameter verifier. If none JWE
	 * objects will be rejected.
	 *
	 * @param jweTypeVerifier The JWE type verifier, {@code null} if not
	 *                        specified.
	 *
	 * @since 8.0
	 */
	void setJWETypeVerifier(final JOSEObjectTypeVerifier<C> jweTypeVerifier);


	/**
	 * Gets the JWE key selector. If none JWE objects will be rejected.
	 *
	 * @return The JWE key selector, {@code null} if not specified.
	 */
	JWEKeySelector<C> getJWEKeySelector();


	/**
	 * Sets the JWE key selector. If none JWE objects will be rejected.
	 *
	 * @param jweKeySelector The JWE key selector, {@code null} if not
	 *                       specified.
	 */
	void setJWEKeySelector(final JWEKeySelector<C> jweKeySelector);


	/**
	 * Gets the factory for creating JWS verifier instances. If none JWS
	 * objects will be rejected.
	 *
	 * @return The JWS verifier factory, {@code null} if not specified.
	 */
	JWSVerifierFactory getJWSVerifierFactory();


	/**
	 * Sets the factory for creating JWS verifier instances. If none JWS
	 * objects will be rejected.
	 *
	 * @param factory The JWS verifier factory, {@code null} if not
	 *                specified.
	 */
	void setJWSVerifierFactory(final JWSVerifierFactory factory);


	/**
	 * Gets the factory for creating JWE decrypter instances. If none JWE
	 * objects will be rejected.
	 *
	 * @return The JWE decrypter factory, {@code null} if not specified.
	 */
	JWEDecrypterFactory getJWEDecrypterFactory();


	/**
	 * Sets the factory for creating JWE decrypter instances. If none JWE
	 * objects will be rejected.
	 *
	 * @param factory The JWE decrypter factory, {@code null} if not
	 *                specified.
	 */
	void setJWEDecrypterFactory(final JWEDecrypterFactory factory);
}
