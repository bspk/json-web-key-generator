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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * @author jricher
 */
public class ECKeyMaker {

    /**
     * @param crv
     * @param keyUse
     * @param keyAlg
     * @param kid
     * @return
     */
    public static ECKey make(Curve crv, KeyUse keyUse, Algorithm keyAlg, KeyIdGenerator kid) {

        try {
            ECParameterSpec ecSpec = crv.toECParameterSpec();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecSpec);

            KeyPair kp = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

            ECKey ecKey = new ECKey.Builder(crv, pub)
                    .privateKey(priv)
                    .keyID(kid.generate(keyUse, pub.getEncoded()))
                    .algorithm(keyAlg)
                    .keyUse(keyUse)
                    .build();

            return ecKey;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

    }

}
