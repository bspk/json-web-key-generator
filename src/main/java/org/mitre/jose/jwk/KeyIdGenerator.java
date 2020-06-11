package org.mitre.jose.jwk;

import com.nimbusds.jose.jwk.KeyUse;

public interface KeyIdGenerator
{
  String generate(KeyUse keyUse, byte[] pubKey);
}
