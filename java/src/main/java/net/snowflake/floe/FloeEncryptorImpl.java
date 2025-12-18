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
        boolean isTerminal = length < parameterSpec.getPlainTextSegmentLength();
        AeadAad aeadAad = isTerminal ? AeadAad.terminal(segmentCounter) : AeadAad.nonTerminal(segmentCounter);
        // it works as long as AEAD returns auth tag as a part of the ciphertext
        byte[] ciphertextWithAuthTag =
            aeadProvider.encrypt(aeadKey, aeadIv, aeadAad, input, offset, length);
        byte[] encoded = segmentToBytes(isTerminal, aeadIv, ciphertextWithAuthTag);
        segmentCounter++;
        if (isTerminal) {
          closeInternal();
        }
        return encoded;
      } catch (Exception e) {
        throw new FloeException("error while encrypting segment", e);
      }
    });
  }

  private void verifySegmentLength(byte[] input, int offset, int length) {
    if (length > parameterSpec.getPlainTextSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "segment length mismatch, expected at most %d, got %d",
              parameterSpec.getPlainTextSegmentLength(), input.length));
    }
    if (offset < 0 || offset > input.length || input.length - offset < length || length < 0) {
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

  private byte[] segmentToBytes(boolean isTerminal, AeadIv aeadIv, byte[] ciphertextWithAuthTag) {
    int ciphertextSegmentLength = Floe.SEGMENT_SIZE_MARKER_LENGTH + aeadIv.getBytes().length + ciphertextWithAuthTag.length;
    int segmentLengthMarker = isTerminal ? ciphertextSegmentLength : NON_TERMINAL_SEGMENT_SIZE_MARKER;
    ByteBuffer output = ByteBuffer.allocate(ciphertextSegmentLength);
    output.putInt(segmentLengthMarker);
    output.put(aeadIv.getBytes());
    output.put(ciphertextWithAuthTag);
    return output.array();
  }

  @Override
  public boolean isClosed() {
    return super.isClosed();
  }
}
