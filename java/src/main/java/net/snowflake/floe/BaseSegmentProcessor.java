package net.snowflake.floe;

import java.io.Closeable;
import java.util.Arrays;
import java.util.function.Supplier;

abstract class BaseSegmentProcessor implements Closeable {
  protected static final int NON_TERMINAL_SEGMENT_SIZE_MARKER = -1;
  protected static final int headerTagLength = 32;

  protected final FloeParameterSpec parameterSpec;
  protected final FloeIv floeIv;
  protected final MessageKey messageKey;
  protected final FloeAad floeAad;

  protected final KeyDerivator keyDerivator;

  private AeadKey currentAeadKey;

  private boolean isClosed;
  private boolean completedExceptionally;

  BaseSegmentProcessor(FloeParameterSpec parameterSpec, FloeIv floeIv, FloeKey floeKey, FloeAad floeAad) {
    // Check the key length if we can
    if (floeKey.getKey().getFormat().equalsIgnoreCase("RAW")) {
      byte[] rawKey = null;
      try {
        rawKey = floeKey.getKey().getEncoded();
        // We don't care about contents, only the length
        Arrays.fill(rawKey, (byte) 0);
      } catch (final Exception e) {
        // If we cannot access the key then we must trust it is correct
        rawKey = null;
      }
      if (rawKey != null && rawKey.length != parameterSpec.getAead().getKeyLength()) {
        throw new IllegalArgumentException("invalid key length");
      }
    }
    this.parameterSpec = parameterSpec;
    this.floeIv = floeIv;
    this.floeAad = floeAad;
    this.keyDerivator = new KeyDerivator(parameterSpec);
    this.messageKey = keyDerivator.hkdfExpandMessageKey(floeKey, floeIv, floeAad);
  }

  protected byte[] processInternal(Supplier<byte[]> processFunc) {
    assertNotClosed();
    try {
      byte[] result = processFunc.get();
      completedExceptionally = false;
      return result;
    } catch (FloeException e) {
      completedExceptionally = true;
      throw e;
    } catch (Exception e) {
      completedExceptionally = true;
      throw new FloeException(e);
    }
  }

  protected AeadKey getKey(MessageKey messageKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) {
    if (currentAeadKey == null || segmentCounter % parameterSpec.getKeyRotationMask() == 0) {
      // we don't need masking, because we derive a new key only when key rotation happens
      currentAeadKey = deriveKey(messageKey, floeIv, floeAad, segmentCounter);
    }
    return currentAeadKey;
  }

  private AeadKey deriveKey(MessageKey secretKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) {
    return keyDerivator.hkdfExpandAeadKey(
            secretKey,
            floeIv,
            floeAad,
            segmentCounter
    );
  }

  protected void closeInternal() {
    isClosed = true;
  }

  private void assertNotClosed() {
    if (isClosed) {
      throw new IllegalStateException("stream has already been closed");
    }
  }

  @Override
  public void close() {
    if (!isClosed && !completedExceptionally) {
      throw new IllegalStateException("last segment was not processed");
    }
  }

  protected boolean isClosed() {
    return isClosed;
  }
}
