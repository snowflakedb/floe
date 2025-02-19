package net.snowflake.floe;

import net.snowflake.floe.aead.AeadProvider;
import net.snowflake.floe.aead.Gcm;

import java.util.function.Supplier;

public enum Aead {
  AES_GCM_256((byte) 0, "AES", "AES/GCM/NoPadding", 32, 12, 16, 20, 1L << 40, () -> new Gcm(16));

  private final byte id;
  private final String jceKeyTypeName;
  private final String jceFullName;
  private final int keyLength;
  private final int ivLength;
  private final int authTagLength;
  private final int keyRotationMask;
  private final long maxSegmentNumber;
  private final Supplier<AeadProvider> aeadProvider;

  Aead(
      byte id,
      String jceKeyTypeName,
      String jceFullName,
      int keyLength,
      int ivLength,
      int authTagLength,
      int keyRotationMask,
      long maxSegmentNumber,
      Supplier<AeadProvider> aeadProvider) {
    this.jceKeyTypeName = jceKeyTypeName;
    this.jceFullName = jceFullName;
    this.keyLength = keyLength;
    this.id = id;
    this.ivLength = ivLength;
    this.authTagLength = authTagLength;
    this.keyRotationMask = keyRotationMask;
    this.maxSegmentNumber = maxSegmentNumber;
    this.aeadProvider = aeadProvider;
  }

  byte getId() {
    return id;
  }

  public String getJceKeyTypeName() {
    return jceKeyTypeName;
  }

  String getJceFullName() {
    return jceFullName;
  }

  int getKeyLength() {
    return keyLength;
  }

  int getIvLength() {
    return ivLength;
  }

  int getAuthTagLength() {
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
