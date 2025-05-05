package net.snowflake.floe;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import static net.snowflake.floe.BaseSegmentProcessor.headerTagLength;

public class Floe {
  private final FloeParameterSpec parameterSpec;
  private final KeyDerivator keyDerivator;

  private Floe(FloeParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
    this.keyDerivator = new KeyDerivator(parameterSpec);
  }

  public static Floe getInstance(FloeParameterSpec parameterSpec) {
    return new Floe(parameterSpec);
  }

  public FloeEncryptor createEncryptor(SecretKey key, byte[] aad) {
    return createEncryptor(key, aad, new SecureRandom());
  }

  public FloeEncryptor createEncryptor(SecretKey key, byte[] aad, SecureRandom random) {
    FloeKey floeKey = new FloeKey(key);
    FloeIv floeIv = FloeIv.generateRandom(random, parameterSpec.getFloeIvLength());
    FloeAad floeAad = new FloeAad(aad);
    try {
      byte[] parametersEncoded = parameterSpec.getEncodedParams();
      byte[] floeIvBytes = floeIv.getBytes();
      byte[] headerTag = keyDerivator.hkdfExpandHeaderTag(floeKey, floeIv, floeAad);

      ByteBuffer header = ByteBuffer.allocate(parametersEncoded.length + floeIvBytes.length + headerTag.length);
      header.put(parametersEncoded);
      header.put(floeIvBytes);
      header.put(headerTag);
      if (header.hasRemaining()) {
        throw new IllegalArgumentException("Header is too long");
      }
      return new FloeEncryptorImpl(parameterSpec, floeKey, floeIv, floeAad, header.array(), random);
    } catch (Exception e) {
      throw new FloeException(e);
    }
  }

  public FloeDecryptor createDecryptor(SecretKey key, byte[] aad, byte[] floeHeader) {
    FloeKey floeKey = new FloeKey(key);
    FloeAad floeAad = new FloeAad(aad);
    byte[] encodedParams = parameterSpec.getEncodedParams();
    int expectedHeaderLength = encodedParams.length + this.parameterSpec.getFloeIvLength() + headerTagLength;
    if (floeHeader.length != expectedHeaderLength) {
      throw new IllegalArgumentException(String.format("invalid header length, expected %d, got %d", encodedParams.length, expectedHeaderLength));
    }
    ByteBuffer floeHeader1 = ByteBuffer.wrap(floeHeader);

    byte[] encodedParamsFromHeader = new byte[10];
    floeHeader1.get(encodedParamsFromHeader, 0, encodedParamsFromHeader.length);
    if (!MessageDigest.isEqual(encodedParams, encodedParamsFromHeader)) {
      throw new IllegalArgumentException("invalid parameters header");
    }

    byte[] floeIvBytes = new byte[parameterSpec.getFloeIvLength()];
    floeHeader1.get(floeIvBytes);
    FloeIv floeIv = new FloeIv(floeIvBytes);

    byte[] headerTagFromHeader = new byte[headerTagLength];
    floeHeader1.get(headerTagFromHeader);

    byte[] headerTag = keyDerivator.hkdfExpandHeaderTag(floeKey, floeIv, floeAad);
    if (!MessageDigest.isEqual(headerTag, headerTagFromHeader)) {
      throw new IllegalArgumentException("invalid header tag");
    }

    return new FloeDecryptorImpl(parameterSpec, floeKey, floeIv, floeAad);
  }

}
