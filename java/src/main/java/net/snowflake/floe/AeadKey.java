package net.snowflake.floe;

import javax.crypto.SecretKey;

class AeadKey {
  private final SecretKey key;

  AeadKey(SecretKey key) {
    this.key = key;
  }

  SecretKey getKey() {
    return key;
  }
}
