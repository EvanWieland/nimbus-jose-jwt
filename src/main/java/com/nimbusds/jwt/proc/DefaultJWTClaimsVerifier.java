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

package com.nimbusds.jwt.proc;


import java.util.Date;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;


/**
 * Default JWT claims verifier. This class is thread-safe.
 *
 * <p>Performs the following checks:
 *
 * <ol>
 *     <li>If an expiration time (exp) claim is present, makes sure it is
 *         ahead of the current time, else the JWT claims set is rejected.
 *     <li>If a not-before-time (nbf) claim is present, makes sure it is
 *         before the current time, else the JWT claims set is rejected.
 * </ol>
 *
 * <p>This class may be extended to perform additional checks.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-15
 */
@ThreadSafe
public class DefaultJWTClaimsVerifier <C extends SecurityContext> implements JWTClaimsSetVerifier<C>, JWTClaimsVerifier, ClockSkewAware {


	/**
	 * The default maximum acceptable clock skew, in seconds (60).
	 */
	public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;


	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew = DEFAULT_MAX_CLOCK_SKEW_SECONDS;
	
	
	/**
	 * The issued-at time claim requirement.
	 */
	private boolean iatRequired = false;
	
	
	/**
	 * The expiration time claim requirement.
	 */
	private boolean expRequired = false;
	
	
	/**
	 * The not-before time claim requirement.
	 */
	private boolean nbfRequired = false;
	
	
	/**
	 * The required issuer, {@code null} if not specified.
	 */
	private String requiredIssuer;
	
	
	/**
	 * The required audience, {@code null} if not specified.
	 */
	private String requiredAudience;


	@Override
	public int getMaxClockSkew() {
		return maxClockSkew;
	}


	@Override
	public void setMaxClockSkew(int maxClockSkewSeconds) {
		maxClockSkew = maxClockSkewSeconds;
	}
	
	
	/**
	 * Gets the issued-at time ("iat") requirement.
	 *
	 * @return {@code true} if the issued-at time claim is required,
	 *         {@code false} if not.
	 *
	 * @since 8.1
	 */
	public boolean requiresIssuedAtTime() {
		return iatRequired;
	}
	
	
	/**
	 * Sets the issued-at time ("iat") requirement.
	 *
	 * @param iatRequired {@code true} if the issued-at time claim is
	 *                    required, {@code false} if not.
	 *
	 * @since 8.1
	 */
	public void requiresIssuedAtTime(final boolean iatRequired) {
		this.iatRequired = iatRequired;
	}
	
	
	/**
	 * Gets the expiration time ("exp") requirement.
	 *
	 * @return {@code true} if the expiration time claim is required,
	 *         {@code false} if not.
	 *
	 * @since 8.1
	 */
	public boolean requiresExpirationTime() {
		return expRequired;
	}
	
	
	/**
	 * Sets the expiration time ("exp") requirement.
	 *
	 * @param expRequired {@code true} if the expiration time claim is
	 *                    required, {@code false} if not.
	 *
	 * @since 8.1
	 */
	public void requiresExpirationTime(final boolean expRequired) {
		this.expRequired = expRequired;
	}
	
	
	/**
	 * Gets the not-before time ("nbf") requirement.
	 *
	 * @return {@code true} if the not-before time claim is required,
	 *         {@code false} if not.
	 *
	 * @since 8.1
	 */
	public boolean requiresNotBeforeTime() {
		return nbfRequired;
	}
	
	
	/**
	 * Sets the not-before time ("nbf") requirement.
	 *
	 * @param nbfRequired {@code true} if the not-before time claim is
	 *                    required, {@code false} if not.
	 *
	 * @since 8.1
	 */
	public void requiresNotBeforeTime(final boolean nbfRequired) {
		this.nbfRequired = nbfRequired;
	}
	
	
	/**
	 * Gets the required issuer ("iss").
	 *
	 * @return The required issuer, {@code null} if not specified.
	 *
	 * @since 8.1
	 */
	public String getRequiredIssuer() {
		return requiredIssuer;
	}
	
	
	/**
	 * Sets the required issuer ("iss").
	 *
	 * @param iss The required issuer, {@code null} if not specified.
	 *
	 * @since 8.1
	 */
	public void setRequiredIssuer(final String iss) {
		requiredIssuer = iss;
	}
	
	
	/**
	 * Gets the required audience ("aud").
	 *
	 * @return The required audience, {@code null} if not specified.
	 *
	 * @since 8.1
	 */
	public String getRequiredAudience() {
		return requiredAudience;
	}
	
	
	/**
	 * Sets the required audience ("aud").
	 *
	 * @param aud The required audience, {@code null} if not specified.
	 *
	 * @since 8.1
	 */
	public void setRequiredAudience(final String aud) {
		requiredAudience = aud;
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet)
		throws BadJWTException {

		verify(claimsSet, null);
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final C context)
		throws BadJWTException {
		
		if (iatRequired && claimsSet.getIssueTime() == null) {
			throw new BadJWTException("JWT issued-at time missing");
		}
		
		final Date now = new Date();
		
		final Date exp = claimsSet.getExpirationTime();
		
		if (expRequired && exp == null) {
			throw new BadJWTException("JWT expiration time missing");
		}
		
		if (exp != null) {
			
			if (! DateUtils.isAfter(exp, now, maxClockSkew)) {
				throw new BadJWTException("Expired JWT");
			}
		}
		
		final Date nbf = claimsSet.getNotBeforeTime();
		
		if (nbfRequired && nbf == null) {
			throw new BadJWTException("JWT not-before time missing");
		}
		
		if (nbf != null) {
			
			if (! DateUtils.isBefore(nbf, now, maxClockSkew)) {
				throw new BadJWTException("JWT before use time");
			}
		}
		
		if (requiredIssuer != null) {
			String iss = claimsSet.getIssuer();
			if (iss == null) {
				throw new BadJWTException("JWT issuer missing");
			}
			if (! requiredIssuer.equals(iss)) {
				throw new BadJWTException("JWT issuer rejected: " + iss);
			}
		}
		
		if (requiredAudience != null) {
			List<String> audList = claimsSet.getAudience();
			if (audList == null || audList.isEmpty()) {
				throw new BadJWTException("JWT audience missing");
			}
			if (! audList.contains(requiredAudience)) {
				throw new BadJWTException("JWT audience rejected: " + audList);
			}
		}
	}
}
