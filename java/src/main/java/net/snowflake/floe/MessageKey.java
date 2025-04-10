package net.snowflake.floe;

import javax.crypto.SecretKey;

class MessageKey {
  private final SecretKey key;

  public MessageKey(SecretKey key) {
    this.key = key;
  }

  SecretKey getKey() {
    return key;
  }
}
