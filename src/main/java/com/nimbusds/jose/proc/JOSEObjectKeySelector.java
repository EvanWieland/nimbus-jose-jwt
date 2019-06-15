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


import java.security.Key;
import java.util.List;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.KeySourceException;


/**
 * Interface for selecting key candidates for processing a JOSE (JWS or JWE)
 * object. Applications should utilise this interface or a similar framework to
 * determine whether a received JOSE object is eligible for further processing.
 *
 * <p>The interface supports keys selection based on:
 *
 * <ul>
 *     <li>Recognised header parameters referencing the key (e.g. {@code kid},
 *         {@code x5t}).
 *     <li>JOSE object payload parameter (e.g. issuer ({@code iss}) claim in a
 *         signed JWT).
 *     <li>Additional {@link SecurityContext}, if required and set by the
 *         application (e.g. endpoint where the JOSE object was received).
 * </ul>
 *
 * <p>Possible key types:
 *
 * <ul>
 *     <li>{@link javax.crypto.SecretKey} for HMAC keys.
 *     <li>{@link java.security.interfaces.RSAPublicKey} public RSA keys.
 *     <li>{@link java.security.interfaces.ECPublicKey} public EC keys.
 * </ul>
 *
 * @author Josh Cummings
 * @version 2019-06-12
 */
public interface JOSEObjectKeySelector<C extends SecurityContext>  {


	/**
	 * Selects key candidates for verifying a JWS object or decrypting a
	 * JWE object.
	 *
	 * @param jose    The JOSE object. Must not be
	 *                {@code null}.
	 * @param context Optional context of the JOSE object, {@code null} if
	 *                not required.
	 *
	 * @return The key candidates in trial order, empty list if none.
	 *
	 * @throws KeySourceException If a key sourcing exception is
	 *                            encountered, e.g. on remote JWK
	 *                            retrieval.
	 */
	List<? extends Key> selectKeys(final JOSEObject jose, final C context)
		throws KeySourceException;
}
