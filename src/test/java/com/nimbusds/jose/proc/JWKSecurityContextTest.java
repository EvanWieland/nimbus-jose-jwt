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

package com.nimbusds.jose.proc;


import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWK;

public class JWKSecurityContextTest {
	@Test
	public void testGetKeys() throws Exception {
		String json = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
		List<JWK> keys = Arrays.asList(JWK.parse(json));
		JWKSecurityContext context = new JWKSecurityContext(keys);

		Assert.assertEquals(keys, context.getKeys());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorWithNull() {
		new JWKSecurityContext(null);
	}
}
