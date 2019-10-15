/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.JOSEObjectType;


/**
 * JOSE object type (header "typ" parameter) verifier.
 *
 * <p>Example JOSE header with a "typ" (type) parameter set to "at+jwt":
 *
 * <pre>
 * {
 *   "alg" : "ES256",
 *   "typ" : "at+jwt",
 *   "kid" : "123"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-14
 * @since 8.0
 */
public interface JOSEObjectTypeVerifier <C extends SecurityContext> {
	
	
	/**
	 * Verifies the JOSE "typ" (type) header parameter.
	 *
	 * @param type    The "typ" (type) header parameter, {@code null} if
	 *                not set.
	 * @param context Optional context, {@code null} if not required.
	 *
	 * @throws BadJOSEException If the type is rejected.
	 */
	void verify(final JOSEObjectType type, final C context)
		throws BadJOSEException;
}
