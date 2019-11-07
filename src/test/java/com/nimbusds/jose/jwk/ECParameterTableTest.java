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

package com.nimbusds.jose.jwk;


import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import junit.framework.TestCase;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;


/**
 * Tests the EC parameter table.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-03-28
 */
public class ECParameterTableTest extends TestCase {
	
	
	public void testParametersAgainstBouncyCastle() {

		for (Curve crv: Arrays.asList(Curve.P_256, Curve.SECP256K1, Curve.P_384, Curve.P_521)) {

			ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec(crv.getStdName());
			
			ECParameterSpec expectedSpec = new ECNamedCurveSpec(curveParams.getName(),
				curveParams.getCurve(),
				curveParams.getG(),
				curveParams.getN());
			
			// Lookup
			ECParameterSpec spec = ECParameterTable.get(crv);
			
			assertEquals(expectedSpec.getCurve().getField().getFieldSize(), spec.getCurve().getField().getFieldSize());
			assertEquals(expectedSpec.getCurve().getA(), spec.getCurve().getA());
			assertEquals(expectedSpec.getCurve().getB(), spec.getCurve().getB());
			assertEquals(expectedSpec.getGenerator().getAffineX(), spec.getGenerator().getAffineX());
			assertEquals(expectedSpec.getGenerator().getAffineY(), spec.getGenerator().getAffineY());
			assertEquals(expectedSpec.getOrder(), spec.getOrder());
			assertEquals(expectedSpec.getCofactor(), spec.getCofactor());
			
			// Reverse lookup
			assertEquals(crv, ECParameterTable.get(expectedSpec));
		}
	}
}
