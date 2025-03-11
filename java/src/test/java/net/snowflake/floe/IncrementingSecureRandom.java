package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class IncrementingSecureRandom extends SecureRandom {
  private int seed;

  public IncrementingSecureRandom(int seed) {
    this.seed = seed;
  }

  @Override
  public void nextBytes(byte[] bytes) {
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    buffer.putInt(seed++);
  }
}
