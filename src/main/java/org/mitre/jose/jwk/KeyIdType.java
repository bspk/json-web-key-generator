package org.mitre.jose.jwk;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;

/**
 * Key ID (kid) types for generated kids.
 */
public enum KeyIdType implements KeyIdGenerator
{
  /** Key usage plus a timestamp - default */
  UsageTimestamp
  {
    @Override
    public String generate(KeyUse keyUse, byte[] pubKey)
    {
      String prefix = keyUse == null ? "" : keyUse.identifier();
      return prefix + (System.currentTimeMillis() / 1000);
    }
  },

  /** No key ID */
  None
  {
    @Override
    public String generate(KeyUse keyUse, byte[] pubKey)
    {
      return null;
    }
  },
  
  /** Base64 encoded SHA-1 Hash of the Public Key encoded bytes */ 
  Sha1PubKey
  {
    @Override
    public String generate(KeyUse keyUse, byte[] pubKey)
    {
      try
      {
        byte[] bytes = MessageDigest.getInstance("SHA-1").digest(pubKey);
        
        return Base64.encode(bytes).toString();
      }
      catch(NoSuchAlgorithmException e)
      {
        throw new IllegalStateException("SHA-1 is not a valid algorithm!", e);
      }
    }
  };
}
