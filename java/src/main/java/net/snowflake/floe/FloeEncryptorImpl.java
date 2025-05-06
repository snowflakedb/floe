package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

// This class is not thread-safe!
class FloeEncryptorImpl extends BaseSegmentProcessor implements FloeEncryptor {
  private final AeadProvider aeadProvider;
  private final SecureRandom random;

  private long segmentCounter;

  private final byte[] header;

  FloeEncryptorImpl(FloeParameterSpec parameterSpec, FloeKey floeKey, FloeIv floeIv, FloeAad floeAad, byte[] header, SecureRandom random) {
    super(parameterSpec, floeIv, floeKey, floeAad);
    this.aeadProvider = parameterSpec.getAead().getAeadProvider();
    this.header = header;
    this.random = random;
  }

  @Override
  public byte[] getHeader() {
    return header.clone();
  }

  @Override
  public byte[] processSegment(byte[] input) {
    return processSegment(input, 0, input.length);
  }

  @Override
  public byte[] processSegment(byte[] input, int offset, int length) {
    return processInternal(() -> {
      try {
        verifySegmentLength(input, offset, length);
        verifyMaxSegmentNumberNotReached();
        AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
        AeadIv aeadIv =
            AeadIv.generateRandom(
                random, parameterSpec.getAead().getIvLength());
        AeadAad aeadAad = AeadAad.nonTerminal(segmentCounter);
        // it works as long as AEAD returns auth tag as a part of the ciphertext
        byte[] ciphertextWithAuthTag =
            aeadProvider.encrypt(aeadKey, aeadIv, aeadAad, input, offset, length);
        byte[] encoded = segmentToBytes(aeadIv, ciphertextWithAuthTag);
        segmentCounter++;
        return encoded;
      } catch (Exception e) {
        throw new FloeException(e);
      }
    });
  }

  private void verifySegmentLength(byte[] input, int offset, int length) {
    if (length != parameterSpec.getPlainTextSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "segment length mismatch, expected %d, got %d",
              parameterSpec.getPlainTextSegmentLength(), input.length));
    }
    if (offset < 0 || offset > input.length || input.length - offset < length) {
      throw new IllegalArgumentException(
          String.format("invalid offset (%d) and length (%d) for input length (%d)", offset, length, input.length)
      );
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
    return processLastSegment(input, 0, input.length);
  }

  @Override
  public byte[] processLastSegment(byte[] input, int offset, final int length) {
    // just for convenience - streams returns -1 when there is no more data, and we would like to
    // treat it as a last 0-length segment
    if (length == -1) {
      return processLastSegment(input, offset, 0);
    }
    return processInternal(() -> {
      try {
        verifyLastSegmentLength(input, offset, length);
        AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
        AeadIv aeadIv =
            AeadIv.generateRandom(
                random, parameterSpec.getAead().getIvLength());
        AeadAad aeadAad = AeadAad.terminal(segmentCounter);
        byte[] ciphertextWithAuthTag =
            aeadProvider.encrypt(aeadKey, aeadIv, aeadAad, input, offset, length);
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

  private void verifyLastSegmentLength(byte[] input, int offset, int length) {
    if (length > parameterSpec.getPlainTextSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "last segment is too long, got %d, max is %d",
              input.length, parameterSpec.getPlainTextSegmentLength()));
    }
    if (offset < 0 || offset > input.length || input.length - offset < length) {
      throw new IllegalArgumentException(
          String.format("invalid offset (%d) and length (%d) for input length (%d)", offset, length, input.length)
      );
    }
  }

  @Override
  public boolean isClosed() {
    return super.isClosed();
  }
}
