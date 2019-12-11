package org.mitre.jose.jwk;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 *
 */
public class OKPKeyMaker {

	/**
	 * @param keyCurve
	 * @param keyUse
	 * @param keyAlg
	 * @param kid
	 * @return
	 */
	public static JWK make(Curve keyCurve, KeyUse keyUse, Algorithm keyAlg, String kid) {

		try {

			KeyPair keyPair = null;
			if (keyCurve.equals(Curve.Ed25519)) {
				keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
			} else if (keyCurve.equals(Curve.Ed448)) {
				keyPair = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
			} else if (keyCurve.equals(Curve.X25519)) {
				keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
			} else if (keyCurve.equals(Curve.X448)) {
				keyPair = KeyPairGenerator.getInstance("X448").generateKeyPair();
			}

			if (keyPair == null) {
				return null;
			}

			OctetKeyPair jwk = new OctetKeyPair.Builder(keyCurve, Base64URL.encode(keyPair.getPublic().getEncoded()))
				.d(Base64URL.encode(keyPair.getPrivate().getEncoded()))
				.keyUse(keyUse)
				.algorithm(keyAlg)
				.keyID(kid)
				.build();

			return jwk;

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}


	}

}
