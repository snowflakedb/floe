package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

// This class is not thread-safe!
class FloeEncryptorImpl extends BaseSegmentProcessor implements FloeEncryptor {
  private final AeadProvider aeadProvider;
  private final SecureRandom random;

  private long segmentCounter;

  private final byte[] header;

  FloeEncryptorImpl(FloeParameterSpec parameterSpec, FloeKey floeKey, FloeAad floeAad, SecureRandom random) {
    super(parameterSpec, FloeIv.generateRandom(random, parameterSpec.getFloeIvLength()), floeKey, floeAad);
    this.aeadProvider = parameterSpec.getAead().getAeadProvider();
    this.header = buildHeader(floeKey);
    this.random = random;
  }

  private byte[] buildHeader(FloeKey floeKey) {
    try {
      byte[] parametersEncoded = parameterSpec.getEncodedParams();
      byte[] floeIvBytes = floeIv.getBytes();
      byte[] headerTag =
          keyDerivator.hkdfExpandHeaderTag(
              floeKey, floeIv, floeAad);

      ByteBuffer result =
          ByteBuffer.allocate(parametersEncoded.length + floeIvBytes.length + headerTag.length);
      result.put(parametersEncoded);
      result.put(floeIvBytes);
      result.put(headerTag);
      if (result.hasRemaining()) {
        throw new IllegalArgumentException("Header is too long");
      }
      return result.array();
    } catch (Exception e) {
      throw new FloeException(e);
    }
  }

  @Override
  public byte[] getHeader() {
    return header.clone();
  }

  @Override
  public byte[] processSegment(byte[] input) {
    return processInternal(() -> {
      try {
        verifySegmentLength(input);
        verifyMaxSegmentNumberNotReached();
        AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
        AeadIv aeadIv =
            AeadIv.generateRandom(
                random, parameterSpec.getAead().getIvLength());
        AeadAad aeadAad = AeadAad.nonTerminal(segmentCounter);
        // it works as long as AEAD returns auth tag as a part of the ciphertext
        byte[] ciphertextWithAuthTag =
            aeadProvider.encrypt(aeadKey, aeadIv, aeadAad, input);
        byte[] encoded = segmentToBytes(aeadIv, ciphertextWithAuthTag);
        segmentCounter++;
        return encoded;
      } catch (Exception e) {
        throw new FloeException(e);
      }
    });
  }

  private void verifySegmentLength(byte[] input) {
    if (input.length != parameterSpec.getPlainTextSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "segment length mismatch, expected %d, got %d",
              parameterSpec.getPlainTextSegmentLength(), input.length));
    }
  }

  private void verifyMaxSegmentNumberNotReached() {
    if (segmentCounter >= parameterSpec.getMaxSegmentNumber() - 1) {
      throw new IllegalStateException("maximum segment number reached");
    }
  }

  private byte[] segmentToBytes(AeadIv aeadIv, byte[] ciphertextWithAuthTag) {
    ByteBuffer output = ByteBuffer.allocate(parameterSpec.getEncryptedSegmentLength());
    output.putInt(NON_TERMINAL_SEGMENT_SIZE_MARKER);
    output.put(aeadIv.getBytes());
    output.put(ciphertextWithAuthTag);
    return output.array();
  }

  @Override
  public byte[] processLastSegment(byte[] input) {
    return processInternal(() -> {
      try {
        verifyLastSegmentLength(input);
        AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
        AeadIv aeadIv =
            AeadIv.generateRandom(
                random, parameterSpec.getAead().getIvLength());
        AeadAad aeadAad = AeadAad.terminal(segmentCounter);
        byte[] ciphertextWithAuthTag =
            aeadProvider.encrypt(aeadKey, aeadIv, aeadAad, input);
        byte[] lastSegmentBytes = lastSegmentToBytes(aeadIv, ciphertextWithAuthTag);
        closeInternal();
        return lastSegmentBytes;
      } catch (Exception e) {
        throw new FloeException(e);
      }
    });
  }

  private byte[] lastSegmentToBytes(AeadIv aeadIv, byte[] ciphertextWithAuthTag) {
    int lastSegmentLength = 4 + aeadIv.getBytes().length + ciphertextWithAuthTag.length;
    ByteBuffer output = ByteBuffer.allocate(lastSegmentLength);
    output.putInt(lastSegmentLength);
    output.put(aeadIv.getBytes());
    output.put(ciphertextWithAuthTag);
    return output.array();
  }

  private void verifyLastSegmentLength(byte[] input) {
    if (input.length > parameterSpec.getPlainTextSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "last segment is too long, got %d, max is %d",
              input.length, parameterSpec.getPlainTextSegmentLength()));
    }
  }

  @Override
  public boolean isClosed() {
    return super.isClosed();
  }
}
