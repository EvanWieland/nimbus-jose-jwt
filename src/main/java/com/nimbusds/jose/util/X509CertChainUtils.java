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

package com.nimbusds.jose.util;


import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONArray;


/**
 * X.509 certificate chain utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-02-27
 */
public class X509CertChainUtils {

	
	/**
	 * Converts the specified JSON array of strings to a list of Base64
	 * encoded objects.
	 *
	 * @param jsonArray The JSON array to parse. Must not be {@code null}.
	 *
	 * @return The Base64 list.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static List<Base64> toBase64List(final JSONArray jsonArray)
		throws ParseException {

		List<Base64> chain = new LinkedList<>();

		for (int i=0; i < jsonArray.size(); i++) {

			Object item = jsonArray.get(i);

			if (item == null) {
				throw new ParseException("The X.509 certificate at position " + i + " must not be null", 0);
			}

			if  (! (item instanceof String)) {
				throw new ParseException("The X.509 certificate at position " + i + " must be encoded as a Base64 string", 0);
			}

			chain.add(new Base64((String)item));
		}

		return chain;
	}

	
	/**
	 * Prevents public instantiation.
	 */
	private X509CertChainUtils() {}
}