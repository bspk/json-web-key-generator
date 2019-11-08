/**
 *
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
    public static ECKey make(Curve crv, KeyUse keyUse, Algorithm keyAlg, String kid) {

        try {
            ECParameterSpec ecSpec = crv.toECParameterSpec();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(ecSpec);

            KeyPair kp = generator.generateKeyPair();

            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

            ECKey ecKey = new ECKey.Builder(crv, pub)
                    .privateKey(priv)
                    .keyID(kid)
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
