/**
 * 
 */
package org.mitre.jose.jwk;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.Use;

/**
 * @author jricher
 *
 */
public class RSAKeyMaker {

	/**
	 * @param keySize
	 * @param keyUse
	 * @param keyAlg
	 * @param kid
	 * @return
	 */
    public static JWK make(Integer keySize, Use keyUse, Algorithm keyAlg, String kid) {
    	
    	try {
	        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	        generator.initialize(keySize);
	        KeyPair kp = generator.generateKeyPair();
	        
	        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
	        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
	        
	        RSAKey key = new RSAKey(pub, priv, keyUse, keyAlg, kid);
	        
	        return key;
        } catch (NoSuchAlgorithmException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	        return null;
        }
    	
    	
    }

}
