package net.snowflake.floe;

import java.security.SecureRandom;

class FloeIv {
  private final byte[] bytes;

  FloeIv(byte[] bytes) {
    this.bytes = bytes;
  }

  static FloeIv generateRandom(SecureRandom random, int floeIvLength) {
    byte[] iv = new byte[floeIvLength];
    random.nextBytes(iv);
    return new FloeIv(iv);
  }

  byte[] getBytes() {
    return bytes;
  }

  int lengthInBytes() {
    return bytes.length;
  }
}
