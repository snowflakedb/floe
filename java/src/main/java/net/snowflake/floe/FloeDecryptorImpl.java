package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

// This class is not thread-safe!
class FloeDecryptorImpl extends BaseSegmentProcessor implements FloeDecryptor {
  private final AeadProvider aeadProvider;

  private long segmentCounter;

  FloeDecryptorImpl(FloeParameterSpec parameterSpec, FloeKey floeKey, FloeIv floeIv, FloeAad floeAad) {
    super(parameterSpec, floeIv, floeKey, floeAad);
    this.aeadProvider = parameterSpec.getAead().getAeadProvider();
  }

  @Override
  public byte[] processSegment(byte[] ciphertext) {
    return processInternal(() -> {
      ByteBuffer inputBuffer = ByteBuffer.wrap(ciphertext);
      try {
        if (isLastSegment(inputBuffer)) {
          return processLastSegment(inputBuffer);
        } else {
          return processNonLastSegment(inputBuffer);
        }
      } catch (GeneralSecurityException e) {
        throw new FloeException(e);
      }
    });
  }

  private boolean isLastSegment(ByteBuffer inputBuffer) {
    final ByteBuffer workingBuffer = inputBuffer.duplicate();
    return workingBuffer.getInt() != NON_TERMINAL_SEGMENT_SIZE_MARKER;
  }

  private byte[] processNonLastSegment(ByteBuffer inputBuf) throws GeneralSecurityException {
    verifyNonLastSegmentLength(inputBuf);
    verifySegmentSizeMarker(inputBuf);
    AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
    AeadIv aeadIv = AeadIv.from(inputBuf, parameterSpec.getAead().getIvLength());
    AeadAad aeadAad = AeadAad.nonTerminal(segmentCounter);
    byte[] ciphertext = new byte[inputBuf.remaining()];
    inputBuf.get(ciphertext);
    byte[] decrypted =
        aeadProvider.decrypt(aeadKey, aeadIv, aeadAad, ciphertext);
    segmentCounter++;
    return decrypted;
  }

  private void verifyNonLastSegmentLength(ByteBuffer inputBuf) {
    if (inputBuf.capacity() != parameterSpec.getEncryptedSegmentLength()) {
      throw new IllegalArgumentException(
          String.format(
              "segment length mismatch, expected %d, got %d",
              parameterSpec.getEncryptedSegmentLength(), inputBuf.capacity()));
    }
  }

  private void verifySegmentSizeMarker(ByteBuffer inputBuf) {
    int segmentSizeMarker = inputBuf.getInt();
    if (segmentSizeMarker != NON_TERMINAL_SEGMENT_SIZE_MARKER) {
      throw new IllegalArgumentException(
          String.format(
              "segment length marker mismatch, expected: %d, got: %d",
              NON_TERMINAL_SEGMENT_SIZE_MARKER, segmentSizeMarker));
    }
  }

  private byte[] processLastSegment(ByteBuffer inputBuf) throws GeneralSecurityException {
    verifyLastSegmentLength(inputBuf);
    verifyLastSegmentSizeMarker(inputBuf);
    AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
    AeadIv aeadIv = AeadIv.from(inputBuf, parameterSpec.getAead().getIvLength());
    AeadAad aeadAad = AeadAad.terminal(segmentCounter);
    byte[] ciphertext = new byte[inputBuf.remaining()];
    inputBuf.get(ciphertext);
    byte[] decrypted =
        aeadProvider.decrypt(aeadKey, aeadIv, aeadAad, ciphertext);
    closeInternal();
    return decrypted;
  }

  private void verifyLastSegmentLength(ByteBuffer inputBuf) {
    if (inputBuf.capacity()
        < 4 + parameterSpec.getAead().getIvLength() + parameterSpec.getAead().getAuthTagLength()) {
      throw new IllegalArgumentException("last segment is too short");
    }
    if (inputBuf.capacity() > parameterSpec.getEncryptedSegmentLength()) {
      throw new IllegalArgumentException("last segment is too long");
    }
  }

  private void verifyLastSegmentSizeMarker(ByteBuffer inputBuf) {
    int segmentLengthFromSegment = inputBuf.getInt();
    if (segmentLengthFromSegment != inputBuf.remaining() + 4) {
      throw new IllegalArgumentException(
          String.format(
              "last segment length marker mismatch, expected: %d, got: %d",
              inputBuf.capacity(), segmentLengthFromSegment));
    }
  }

  @Override
  public boolean isClosed() {
    return super.isClosed();
  }
}
