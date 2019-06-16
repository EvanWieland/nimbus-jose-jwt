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

package com.nimbusds.jwt.proc;


import java.security.Key;
import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * Interface for selecting key candidates for processing a signed JWT which
 * provides access to the JWT claims set in addition to the JWS header.
 *
 * <p>The interface supports keys selection based on:
 *
 * <ul>
 *     <li>Recognised header parameter(s) referencing the key (e.g.
 *         {@code kid}, {@code x5t}).
 *     <li>JWT claim(s) (e.g. issuer ({@code iss}) to locate a JWK set).
 *     <li>Additional {@link SecurityContext}, if required and set by the
 *         application (e.g. endpoint where the JWT was received).
 * </ul>
 *
 * <p>See the simpler {@link com.nimbusds.jose.proc.JWSKeySelector} if the
 * application doesn't use JWT claim(s) to select the key candidates.
 *
 * <p>Possible key types:
 *
 * <ul>
 *     <li>{@link javax.crypto.SecretKey} for HMAC keys.
 *     <li>{@link java.security.interfaces.RSAPublicKey} public RSA keys.
 *     <li>{@link java.security.interfaces.ECPublicKey} public EC keys.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-06-16
 */
public interface JWTClaimsSetAwareJWSKeySelector<C extends SecurityContext> {
	
	
	/**
	 * Selects key candidates for verifying a signed JWT.
	 *
	 * @param header    The JWS header. Must not be {@code null}.
	 * @param claimsSet The JWT claims set (not verified). Must not be
	 *                  {@code null}.
	 * @param context   Optional context of the JOSE object, {@code null}
	 *                  if not required.
	 *
	 * @return The key candidates in trial order, empty list if none.
	 *
	 * @throws KeySourceException If a key sourcing exception is
	 *                            encountered, e.g. on remote JWK
	 *                            retrieval.
	 */
	List<? extends Key> selectKeys(final JWSHeader header, final JWTClaimsSet  claimsSet, final C context)
		throws KeySourceException;
}

