package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

import static net.snowflake.floe.BaseSegmentProcessor.headerTagLength;

public class FloeParameterSpec {
  private final Aead aead;
  private final Hash hash;
  private final int encryptedSegmentLength;
  private final int floeIvLength;
  private final Integer keyRotationModuloOverride;
  private final Long maxSegmentNumberOverride;
  private final byte[] encodedParams;

  public FloeParameterSpec(Aead aead, Hash hash, int encryptedSegmentLength, int floeIvLength) {
    this(
        aead,
        hash,
        encryptedSegmentLength,
        floeIvLength,
        null,
        null);
  }

  FloeParameterSpec(
      Aead aead,
      Hash hash,
      int encryptedSegmentLength,
      int floeIvLength,
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
    if (floeIvLength <= 0) {
      throw new IllegalArgumentException("floeIvLength must be > 0");
    }
    this.encodedParams = paramEncode();
  }

  private byte[] paramEncode() {
    ByteBuffer result = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
    result.put(aead.getId());
    result.put(hash.getId());
    result.putInt(encryptedSegmentLength);
    result.putInt(floeIvLength);
    return result.array();
  }

  public Aead getAead() {
    return aead;
  }

  public Hash getHash() {
    return hash;
  }

  public int getFloeIvLength() {
    return floeIvLength;
  }

  public int getEncryptedSegmentLength() {
    return encryptedSegmentLength;
  }

  public int getPlainTextSegmentLength() {
    // sizeof(int) == 4, file size is a part of the segment ciphertext
    return encryptedSegmentLength - aead.getIvLength() - aead.getAuthTagLength() - 4;
  }

  int getKeyRotationMask() {
    return Optional.ofNullable(keyRotationModuloOverride).orElse(aead.getKeyRotationMask());
  }

  long getMaxSegmentNumber() {
    return Optional.ofNullable(maxSegmentNumberOverride).orElse(aead.getMaxSegmentNumber());
  }

  public byte[] getEncodedParams() {
    return encodedParams.clone();
  }

  int getHeaderSize() {
    return encodedParams.length + floeIvLength + headerTagLength;
  }
}
