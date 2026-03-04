package net.snowflake.floe;

import java.util.function.Supplier;

public enum Aead {
  AES_GCM_256((byte) 0, "AES", 32, 12, 16, 20, 1L << 40, () -> new GcmAead(16));

  private final byte id;
  private final String jceKeyTypeName;
  private final int keyLength;
  private final int ivLength;
  private final int authTagLength;
  private final int keyRotationMask;
  private final long maxSegmentNumber;
  private final Supplier<AeadProvider> aeadProvider;

  Aead(
      byte id,
      String jceKeyTypeName,
      int keyLength,
      int ivLength,
      int authTagLength,
      int keyRotationMask,
      long maxSegmentNumber,
      Supplier<AeadProvider> aeadProvider) {
    this.jceKeyTypeName = jceKeyTypeName;
    this.keyLength = keyLength;
    this.id = id;
    this.ivLength = ivLength;
    this.authTagLength = authTagLength;
    this.keyRotationMask = keyRotationMask;
    this.maxSegmentNumber = maxSegmentNumber;
    this.aeadProvider = aeadProvider;
  }

  public static Aead from(byte id) {
    if (id == 0) {
      return AES_GCM_256;
    }
    throw new IllegalArgumentException("Invalid AEAD ID");
  }

  public byte getId() {
    return id;
  }

  public String getJceKeyTypeName() {
    return jceKeyTypeName;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public int getIvLength() {
    return ivLength;
  }

  public int getAuthTagLength() {
    return authTagLength;
  }

  int getKeyRotationMask() {
    return keyRotationMask;
  }

  long getMaxSegmentNumber() {
    return maxSegmentNumber;
  }

  AeadProvider getAeadProvider() {
    return aeadProvider.get();
  }
}
