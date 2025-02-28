package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

// This class is not thread-safe!
class FloeDecryptorImpl extends BaseSegmentProcessor implements FloeDecryptor {
  private final FloeIv floeIv;
  private final AeadProvider aeadProvider;

  private long segmentCounter;

  FloeDecryptorImpl(
      FloeParameterSpec parameterSpec, FloeKey floeKey, FloeAad floeAad, byte[] floeHeaderAsBytes) {
    super(parameterSpec, floeKey, floeAad);
    byte[] encodedParams = this.parameterSpec.getEncodedParams();
    int expectedHeaderLength = encodedParams.length
        + this.parameterSpec.getFloeIvLength()
        + headerTagLength;
    if (floeHeaderAsBytes.length
        != expectedHeaderLength) {
      throw new IllegalArgumentException(String.format("invalid header length, expected %d, got %d", encodedParams.length, expectedHeaderLength));
    }
    ByteBuffer floeHeader = ByteBuffer.wrap(floeHeaderAsBytes);

    byte[] encodedParamsFromHeader = new byte[10];
    floeHeader.get(encodedParamsFromHeader, 0, encodedParamsFromHeader.length);
    if (!MessageDigest.isEqual(encodedParams, encodedParamsFromHeader)) {
      throw new IllegalArgumentException("invalid parameters header");
    }

    byte[] floeIvBytes = new byte[this.parameterSpec.getFloeIvLength()];
    floeHeader.get(floeIvBytes, 0, floeIvBytes.length);
    this.floeIv = new FloeIv(floeIvBytes);
    this.aeadProvider = parameterSpec.getAead().getAeadProvider();

    byte[] headerTagFromHeader = new byte[headerTagLength];
    floeHeader.get(headerTagFromHeader, 0, headerTagFromHeader.length);

    try {
      byte[] headerTag =
          keyDerivator.hkdfExpand(
              this.floeKey, floeIv, this.floeAad, HeaderTagFloePurpose.INSTANCE, headerTagLength);
      if (!MessageDigest.isEqual(headerTag, headerTagFromHeader)) {
        throw new IllegalArgumentException("invalid header tag");
      }
    } catch (Exception e) {
      throw new FloeException("error while validating FLOE header", e);
    }
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
    AeadKey aeadKey = getKey(floeKey, floeIv, floeAad, segmentCounter);
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
    AeadKey aeadKey = getKey(floeKey, floeIv, floeAad, segmentCounter);
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
