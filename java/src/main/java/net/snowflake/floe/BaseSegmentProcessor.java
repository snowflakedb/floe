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
  protected final FloeIv floeIv;
  protected final MessageKey messageKey;
  protected final FloeAad floeAad;

  protected final KeyDerivator keyDerivator;

  private AeadKey currentAeadKey;

  private boolean isClosed;
  private boolean completedExceptionally;

  BaseSegmentProcessor(FloeParameterSpec parameterSpec, FloeIv floeIv, FloeKey floeKey, FloeAad floeAad) {
    this.parameterSpec = parameterSpec;
    this.floeIv = floeIv;
    this.floeAad = floeAad;
    this.keyDerivator = new KeyDerivator(parameterSpec);
    try {
      this.messageKey = new MessageKey(new SecretKeySpec(keyDerivator.hkdfExpandMessageKey(floeKey, floeIv, floeAad, parameterSpec.getHash().getLength()), "FLOE_MSG_KEY"));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new FloeException(e);
    }
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

  protected AeadKey getKey(MessageKey messageKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) throws NoSuchAlgorithmException, InvalidKeyException {
    if (currentAeadKey == null || segmentCounter % parameterSpec.getKeyRotationMask() == 0) {
      // we don't need masking, because we derive a new key only when key rotation happens
      currentAeadKey = deriveKey(messageKey, floeIv, floeAad, segmentCounter);
    }
    return currentAeadKey;
  }

  private AeadKey deriveKey(MessageKey secretKey, FloeIv floeIv, FloeAad floeAad, long segmentCounter) throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] keyBytes =
        keyDerivator.hkdfExpandAeadKey(
            secretKey,
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
