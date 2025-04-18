package net.snowflake.floe;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class AeadKey {
  private final SecretKey key;

  AeadKey(byte[] key, String algorithm) {
    this.key = new SecretKeySpec(key, algorithm);
  }

  SecretKey getKey() {
    return key;
  }
}
