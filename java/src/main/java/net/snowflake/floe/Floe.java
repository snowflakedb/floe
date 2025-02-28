package net.snowflake.floe;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class Floe {
  private final FloeParameterSpec parameterSpec;

  private Floe(FloeParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
  }

  public static Floe getInstance(FloeParameterSpec parameterSpec) {
    return new Floe(parameterSpec);
  }

  public FloeEncryptor createEncryptor(SecretKey key, byte[] aad) {
    return createEncryptor(key, aad, new SecureRandom());
  }

  public FloeEncryptor createEncryptor(SecretKey key, byte[] aad, SecureRandom random) {
    return new FloeEncryptorImpl(parameterSpec, new FloeKey(key), new FloeAad(aad), random);
  }

  public FloeDecryptor createDecryptor(SecretKey key, byte[] aad, byte[] floeHeader) {
    return new FloeDecryptorImpl(parameterSpec, new FloeKey(key), new FloeAad(aad), floeHeader);
  }
}
