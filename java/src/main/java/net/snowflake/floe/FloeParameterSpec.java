package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import static net.snowflake.floe.BaseSegmentProcessor.headerTagLength;

public class FloeParameterSpec {
  public static final FloeParameterSpec GCM256_SHA384_4K = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 4 * 1024, 32);
  public static final FloeParameterSpec GCM256_SHA384_1M = new FloeParameterSpec(Aead.AES_GCM_256, Hash.SHA384, 1024 * 1024, 32);

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
    if (floeIvLength != 32) {
      throw new IllegalArgumentException("Currently, floeIvLength must be equal to 32");
    }
    this.encodedParams = paramEncode();
  }

  public static FloeParameterSpec fromHeader(byte[] header) {
    return paramDecode(header);
  }

  private byte[] paramEncode() {
    ByteBuffer result = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
    result.put(aead.getId());
    result.put(hash.getId());
    result.putInt(encryptedSegmentLength);
    result.putInt(floeIvLength);
    return result.array();
  }

  private static FloeParameterSpec paramDecode(byte[] header) {
    ByteBuffer headerBuf = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
    Aead aead = Aead.from(headerBuf.get());
    Hash hash = Hash.from(headerBuf.get());
    int encryptedSegmentLength = headerBuf.getInt();
    int floeIvLength = headerBuf.getInt();
    return new FloeParameterSpec(aead, hash, encryptedSegmentLength, floeIvLength);
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
    return encryptedSegmentLength - aead.getIvLength() - aead.getAuthTagLength() - Floe.SEGMENT_SIZE_MARKER_LENGTH;
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

  public int getHeaderSize() {
    return encodedParams.length + floeIvLength + headerTagLength;
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;
    FloeParameterSpec that = (FloeParameterSpec) o;
    return encryptedSegmentLength == that.encryptedSegmentLength
        && floeIvLength == that.floeIvLength
        && aead == that.aead
        && hash == that.hash
        && Objects.equals(keyRotationModuloOverride, that.keyRotationModuloOverride)
        && Objects.equals(maxSegmentNumberOverride, that.maxSegmentNumberOverride)
        && Objects.deepEquals(encodedParams, that.encodedParams);
  }

  @Override
  public int hashCode() {
    return Objects.hash(aead, hash, encryptedSegmentLength, floeIvLength, keyRotationModuloOverride, maxSegmentNumberOverride, Arrays.hashCode(encodedParams));
  }

  @Override
  public String toString() {
    return String.format("%s{encryptedSegmentLength=%s, floeIvLength=%s, aeadId=%s, hashId=%s}", this.getClass().getCanonicalName(), encryptedSegmentLength, floeIvLength, aead.getId(), hash.getId());
  }
}
