package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

class AeadIv {
  private final byte[] bytes;

  AeadIv(byte[] bytes) {
    this.bytes = bytes;
  }

  static AeadIv generateRandom(SecureRandom random, int ivLength) {
    byte[] iv = new byte[ivLength];
    random.nextBytes(iv);
    return new AeadIv(iv);
  }

  static AeadIv from(ByteBuffer buffer, int ivLength) {
    byte[] bytes = new byte[ivLength];
    buffer.get(bytes);
    return new AeadIv(bytes);
  }

  byte[] getBytes() {
    return bytes;
  }
}
