/*
 * Copyright 2019 The MITRE Corporation and
 *   the MIT Kerberos and Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.jose.jwk;

import java.security.SecureRandom;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 */
public class OctetSequenceKeyMaker {

    /**
     * @param keySize in bits
     * @return
     */
    public static OctetSequenceKey make(Integer keySize, KeyUse use, Algorithm alg, KeyIdGenerator kid) {

        // holder for the random bytes
        byte[] bytes = new byte[keySize / 8];

        // make a random number generator and fill our holder
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(bytes);

        Base64URL encoded = Base64URL.encode(bytes);

        // make a key
        OctetSequenceKey octetSequenceKey = new OctetSequenceKey.Builder(encoded)
                .keyID(kid.generate(use, bytes))
                .algorithm(alg)
                .keyUse(use)
                .build();

        return octetSequenceKey;
    }

}
