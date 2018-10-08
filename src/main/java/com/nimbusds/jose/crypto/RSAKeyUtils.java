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

package com.nimbusds.jose.crypto;


import java.security.PrivateKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;


/**
 * RSA JWK conversion utility.
 */
class RSAKeyUtils {
	
	
	/**
	 * Returns the private RSA key of the specified RSA JWK. Supports
	 * PKCS#11 keys stores.
	 *
	 * @param rsaJWK The RSA JWK. Must not be {@code null}.
	 *
	 * @return The private RSA key.
	 *
	 * @throws JOSEException If the RSA JWK doesn't contain a private part.
	 */
	static PrivateKey toRSAPrivateKey(final RSAKey rsaJWK)
		throws JOSEException {
		
		if (! rsaJWK.isPrivate()) {
			throw new JOSEException("The RSA JWK doesn't contain a private part");
		}
		
		return rsaJWK.toPrivateKey();
	}
}
