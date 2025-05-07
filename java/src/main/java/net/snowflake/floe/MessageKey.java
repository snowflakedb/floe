package net.snowflake.floe;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class MessageKey {
  private final SecretKey key;

  MessageKey(byte[] key) {
    this.key = new SecretKeySpec(key, "FLOE_MSG_KEY");
  }

  SecretKey getKey() {
    return key;
  }
}
