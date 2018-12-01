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

package com.nimbusds.jose.jwk.source;


import java.util.Date;
import java.util.concurrent.TimeUnit;

import com.nimbusds.jose.jwk.JWKSet;
import junit.framework.TestCase;


public class DefaultJWKSetCacheTest extends TestCase {
	
	
	public void testDefaultConstructor() throws InterruptedException {
		
		DefaultJWKSetCache cache = new DefaultJWKSetCache();
		
		assertEquals(5, DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES);
		assertEquals(DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES, cache.getLifespan(TimeUnit.MINUTES));
		
		assertNull(cache.get());
		
		assertEquals(-1L, cache.getPutTimestamp());
		
		assertFalse(cache.isExpired());
		
		JWKSet jwkSet = new JWKSet();
		
		cache.put(jwkSet);
		
		assertEquals(jwkSet, cache.get());
		
		assertTrue(new Date().getTime() >= cache.getPutTimestamp());
		
		Thread.sleep(1L);

		assertFalse(cache.isExpired());
		
		
		cache.put(null); // clear
		assertNull(cache.get());
		assertFalse(cache.isExpired());
	}
	
	
	public void testParamConstructor() throws InterruptedException {
		
		DefaultJWKSetCache cache = new DefaultJWKSetCache(1L, TimeUnit.SECONDS);
		
		assertEquals(1L, cache.getLifespan(TimeUnit.SECONDS));
		
		assertNull(cache.get());
		
		assertEquals(-1L, cache.getPutTimestamp());
		
		assertFalse(cache.isExpired());
		
		JWKSet jwkSet = new JWKSet();
		
		cache.put(jwkSet);
		
		assertEquals(jwkSet, cache.get());
		
		assertTrue(cache.getPutTimestamp() >= new Date().getTime());
		
		assertFalse(cache.isExpired());
		
		Thread.sleep(2 * 1000L);
		
		assertNull("Expired", cache.get());
		
		assertTrue(cache.isExpired());
	}
	
	
	public void testNoExpiration() {
		
		DefaultJWKSetCache cache = new DefaultJWKSetCache(-1L, null);
		
		assertEquals(-1L, cache.getLifespan(TimeUnit.HOURS));
		
		assertNull(cache.get());
		
		assertFalse(cache.isExpired());
		
		assertEquals(-1L, cache.getPutTimestamp());
		
		JWKSet jwkSet = new JWKSet();
		
		cache.put(jwkSet);
		
		assertEquals(jwkSet, cache.get());
		
		assertTrue(cache.getPutTimestamp() >= new Date().getTime());
		
		assertFalse(cache.isExpired());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/289/clearing-the-jwksetcache-must-undefine-the
	public void testCacheClearMustUndefinePutTimestamp() {
		
		DefaultJWKSetCache cache = new DefaultJWKSetCache();
		
		assertNull(cache.get());
		assertEquals(-1L, cache.getPutTimestamp());
		assertEquals(DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES, cache.getLifespan(TimeUnit.MINUTES));
		assertFalse(cache.isExpired());
		
		
		JWKSet jwkSet = new JWKSet();
		
		cache.put(jwkSet);
		
		assertTrue(cache.getPutTimestamp() > 0);
		assertEquals(DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES, cache.getLifespan(TimeUnit.MINUTES));
		assertFalse(cache.isExpired());
		
		// clear cache
		cache.put(null);
		
		assertNull(cache.get());
		assertEquals(-1L, cache.getPutTimestamp());
		assertEquals(DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES, cache.getLifespan(TimeUnit.MINUTES));
		assertFalse(cache.isExpired());
	}
}
