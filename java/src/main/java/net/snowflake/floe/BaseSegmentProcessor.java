package net.snowflake.floe;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Closeable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.function.Supplier;

abstract class BaseSegmentProcessor implements Closeable {
  protected static final int NON_TERMINAL_SEGMENT_SIZE_MARKER = -1;
  protected static final int headerTagLength = 32;

  protected final FloeParameterSpec parameterSpec;
  protected final FloeKey floeKey;
  protected final FloeAad floeAad;

  protected final KeyDerivator keyDerivator;

  private AeadKey currentAeadKey;

  private boolean isClosed;
  private boolean completedExceptionally;

  BaseSegmentProcessor(FloeParameterSpec parameterSpec, FloeKey floeKey, FloeAad floeAad) {
    this.parameterSpec = parameterSpec;
    this.floeKey = floeKey;
    this.floeAad = floeAad;
    this.keyDerivator = new KeyDerivator(parameterSpec);
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

  protected AeadKey getKey(FloeKey floeKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) throws NoSuchAlgorithmException, InvalidKeyException {
    if (currentAeadKey == null || segmentCounter % parameterSpec.getKeyRotationMask() == 0) {
      // we don't need masking, because we derive a new key only when key rotation happens
      currentAeadKey = deriveKey(floeKey, floeIv, floeAad, segmentCounter);
    }
    return currentAeadKey;
  }

  private AeadKey deriveKey(FloeKey floeKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] keyBytes =
        keyDerivator.hkdfExpand(
            floeKey,
            floeIv,
            floeAad,
            new DekTagFloePurpose(segmentCounter),
            parameterSpec.getAead().getKeyLength());
    SecretKey key = new SecretKeySpec(keyBytes, parameterSpec.getAead().getJceKeyTypeName());
    return new AeadKey(key);
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
