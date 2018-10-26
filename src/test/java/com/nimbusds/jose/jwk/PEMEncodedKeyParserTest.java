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

package com.nimbusds.jose.jwk;

import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class PEMEncodedKeyParserTest {

    // EC
    @Test
    public void loadCertificate() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.EC_CERT_PEM);
        final ECPublicKey key = (ECPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
    }

    @Test
    public void loadPrivateKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.EC_PRIVATE_KEY_PEM);
        final ECPrivateKey key = (ECPrivateKey) credential.get(0).getPrivate();
        assertNotNull(key);
    }

    @Test
    public void loadPublicFromPrivateKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.EC_PRIVATE_KEY_PEM);
        final ECPublicKey key = (ECPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
    }

    @Test
    public void loadPublicKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.EC_PUBLIC_KEY_PEM);
        final ECPublicKey key = (ECPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
        assertNull(credential.get(0).getPrivate());
    }

    // RSA
    @Test
    public void loadRsaCertificate() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.RSA_CERT_PEM);
        final RSAPublicKey key = (RSAPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
    }

    @Test
    public void loadRsaPrivateKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);
        final RSAPrivateKey key = (RSAPrivateKey) credential.get(0).getPrivate();
        assertNotNull(key);
    }

    @Test
    public void loadRsaPublicFromPrivateKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);
        final RSAPublicKey key = (RSAPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
    }

    @Test
    public void loadRsaPublicKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys(SamplePEMEncodedObjects.RSA_PUBLIC_KEY_PEM);
        final RSAPublicKey key = (RSAPublicKey) credential.get(0).getPublic();
        assertNotNull(key);
    }

    // malformed, no keys
    @Test
    public void loadEmptyKey() throws Exception {
        final List<KeyPair> credential = PEMEncodedKeyParser.parseKeys("");
        assertTrue(credential.isEmpty());
    }
}
