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

package com.nimbusds.jose.util;


import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;

import com.nimbusds.jose.jwk.SampleCertificates;
import junit.framework.TestCase;


public class X509CertChainUtilsTest extends TestCase {
	
	
	public void testToBase64List_nullSafe()
		throws ParseException {
		
		assertNull(X509CertChainUtils.toBase64List(null));
	}
	
	
	public void testParseSample()
		throws ParseException {
		
		List<X509Certificate> chain = X509CertChainUtils.parse(SampleCertificates.SAMPLE_X5C_RSA);
		
		assertEquals("SHA256withRSA", chain.get(0).getSigAlgName());
		assertEquals("SHA256withRSA", chain.get(1).getSigAlgName());
		assertEquals("SHA1withRSA",   chain.get(2).getSigAlgName());
		
		assertEquals("CN=www.oracle.com, OU=Content Management Services IT, O=Oracle Corporation, L=Redwood Shores, ST=California, C=US", chain.get(0).getSubjectDN().getName());
		assertEquals("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US", chain.get(1).getSubjectDN().getName());
		assertEquals("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US", chain.get(2).getSubjectDN().getName());
		
		assertEquals("CN=GeoTrust RSA CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US", chain.get(0).getIssuerDN().getName());
		assertEquals("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US", chain.get(1).getIssuerDN().getName());
		assertEquals("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US", chain.get(2).getIssuerDN().getName());
		
		assertEquals("X.509", chain.get(0).getType());
		assertEquals("X.509", chain.get(1).getType());
		assertEquals("X.509", chain.get(2).getType());
		
		assertEquals("RSA", chain.get(0).getPublicKey().getAlgorithm());
		assertEquals("RSA", chain.get(1).getPublicKey().getAlgorithm());
		assertEquals("RSA", chain.get(2).getPublicKey().getAlgorithm());
		
		assertEquals(2352, ByteUtils.bitLength(chain.get(0).getPublicKey().getEncoded()));
		assertEquals(2352, ByteUtils.bitLength(chain.get(1).getPublicKey().getEncoded()));
		assertEquals(2352, ByteUtils.bitLength(chain.get(2).getPublicKey().getEncoded()));
	}
}
