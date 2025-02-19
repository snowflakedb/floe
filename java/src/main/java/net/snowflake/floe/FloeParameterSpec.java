package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

public class FloeParameterSpec {
  private final Aead aead;
  private final Hash hash;
  private final int encryptedSegmentLength;
  private final FloeIvLength floeIvLength;
  private final Integer keyRotationModuloOverride;
  private final Long maxSegmentNumberOverride;

  public FloeParameterSpec(Aead aead, Hash hash, int encryptedSegmentLength, int floeIvLength) {
    this(
        aead,
        hash,
        encryptedSegmentLength,
        new FloeIvLength(floeIvLength),
        null,
        null);
  }

  FloeParameterSpec(
      Aead aead,
      Hash hash,
      int encryptedSegmentLength,
      FloeIvLength floeIvLength,
      Integer keyRotationModuloOverride,
      Long maxSegmentNumberOverride) {
    this.aead = aead;
    this.hash = hash;
    this.encryptedSegmentLength = encryptedSegmentLength;
    this.floeIvLength = floeIvLength;
    this.keyRotationModuloOverride = keyRotationModuloOverride;
    this.maxSegmentNumberOverride = maxSegmentNumberOverride;
    if (encryptedSegmentLength <= 0) {
      throw new IllegalArgumentException("encryptedSegmentLength must be > 0");
    }
    if (floeIvLength.getLength() <= 0) {
      throw new IllegalArgumentException("floeIvLength must be > 0");
    }
  }

  byte[] paramEncode() {
    ByteBuffer result = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
    result.put(aead.getId());
    result.put(hash.getId());
    result.putInt(encryptedSegmentLength);
    result.putInt(floeIvLength.getLength());
    return result.array();
  }

  public Aead getAead() {
    return aead;
  }

  public Hash getHash() {
    return hash;
  }

  FloeIvLength getFloeIvLength() {
    return floeIvLength;
  }

  int getEncryptedSegmentLength() {
    return encryptedSegmentLength;
  }

  int getPlainTextSegmentLength() {
    // sizeof(int) == 4, file size is a part of the segment ciphertext
    return encryptedSegmentLength - aead.getIvLength() - aead.getAuthTagLength() - 4;
  }

  int getKeyRotationMask() {
    return Optional.ofNullable(keyRotationModuloOverride).orElse(aead.getKeyRotationMask());
  }

  long getMaxSegmentNumber() {
    return Optional.ofNullable(maxSegmentNumberOverride).orElse(aead.getMaxSegmentNumber());
  }
}
