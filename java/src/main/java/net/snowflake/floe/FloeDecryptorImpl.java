package net.snowflake.floe;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

// This class is not thread-safe!
class FloeDecryptorImpl extends BaseSegmentProcessor implements FloeDecryptor {
  private final AeadProvider aeadProvider;
  private final int minimalSegmentLength = 4 /* segment size marker */ + parameterSpec.getAead().getIvLength() + parameterSpec.getAead().getAuthTagLength();

  private long segmentCounter;

  FloeDecryptorImpl(FloeParameterSpec parameterSpec, FloeKey floeKey, FloeIv floeIv, FloeAad floeAad) {
    super(parameterSpec, floeIv, floeKey, floeAad);
    this.aeadProvider = parameterSpec.getAead().getAeadProvider();
  }

  @Override
  public byte[] processSegment(byte[] input) {
    return processSegment(input, 0, input.length);
  }

  @Override
  public byte[] processSegment(byte[] input, int offset, final int length) {
    if (length == -1) {
      return processSegment(input, offset, 0);
    }
    return processInternal(() -> {
      ByteBuffer inputBuf = ByteBuffer.wrap(input, offset, length);
      try {
        verifyMinimalSegmentLength(inputBuf);
        verifySegmentNotTooLong(inputBuf);
        boolean isTerminal = isTerminal(inputBuf);
        verifySegmentSizeWithSegmentSizeMarker(inputBuf, isTerminal);
        AeadKey aeadKey = getKey(messageKey, floeIv, floeAad, segmentCounter);
        AeadIv aeadIv = AeadIv.from(inputBuf, parameterSpec.getAead().getIvLength());
        AeadAad aeadAad = isTerminal ? AeadAad.terminal(segmentCounter) : AeadAad.nonTerminal(segmentCounter);
        byte[] decrypted =
            aeadProvider.decrypt(aeadKey, aeadIv, aeadAad, inputBuf.array(), inputBuf.position(), inputBuf.remaining());
        if (isTerminal) {
          closeInternal();
        }
        segmentCounter++;
        return decrypted;
      } catch (GeneralSecurityException e) {
        throw new FloeException(e);
      }
    });
  }

  private void verifyMinimalSegmentLength(ByteBuffer inputBuf) {
    if (inputBuf.remaining() < minimalSegmentLength) {
      throw new IllegalArgumentException(String.format("segment length too short, expected at least %d, got %d", minimalSegmentLength, inputBuf.remaining()));
    }
  }

  private boolean isTerminal(ByteBuffer inputBuf) {
    final ByteBuffer workingBuffer = inputBuf.duplicate();
    return workingBuffer.getInt() != NON_TERMINAL_SEGMENT_SIZE_MARKER;
  }

  private void verifySegmentNotTooLong(ByteBuffer inputBuf) {
    if (inputBuf.remaining() > parameterSpec.getEncryptedSegmentLength()) {
      throw new IllegalArgumentException(String.format("segment length mismatch, expected at most %d, got %d", parameterSpec.getEncryptedSegmentLength(), inputBuf.remaining()));
    }
  }

  private void verifySegmentSizeWithSegmentSizeMarker(ByteBuffer inputBuf, boolean isTerminal) {
    int segmentSize = inputBuf.remaining();
    int segmentSizeMarker = inputBuf.getInt();
    if (!isTerminal && segmentSizeMarker == -1) {
      return;
    }
    if (segmentSize != segmentSizeMarker) {
      throw new IllegalArgumentException(String.format("segment length mismatch, expected %d, got %d", segmentSizeMarker, segmentSize));
    }
  }

  @Override
  public boolean isClosed() {
    return super.isClosed();
  }
}
