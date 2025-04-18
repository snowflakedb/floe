package net.snowflake.floe;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static net.snowflake.floe.BaseSegmentProcessor.headerTagLength;

class KeyDerivator {
  private final FloeParameterSpec parameterSpec;

  KeyDerivator(FloeParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
  }

  MessageKey hkdfExpandMessageKey(FloeKey floeKey, FloeIv floeIv, FloeAad floeAad) throws NoSuchAlgorithmException, InvalidKeyException {
    return new MessageKey((hkdfExpand(floeKey.getKey(), floeIv, floeAad, MessageKeyPurpose.INSTANCE, parameterSpec.getHash().getLength())));
  }

  AeadKey hkdfExpandAeadKey(MessageKey messageKey, FloeIv floeIv, FloeAad floeAad, DekTagFloePurpose purpose) throws NoSuchAlgorithmException, InvalidKeyException {
    return new AeadKey(hkdfExpand(messageKey.getKey(), floeIv, floeAad, purpose, parameterSpec.getAead().getKeyLength()), parameterSpec.getAead().getJceKeyTypeName());
  }

  byte[] hkdfExpandHeaderTag(FloeKey floeKey, FloeIv floeIv, FloeAad floeAad) throws NoSuchAlgorithmException, InvalidKeyException {
    return hkdfExpand(floeKey.getKey(), floeIv, floeAad, HeaderTagFloePurpose.INSTANCE, headerTagLength);
  }

  private byte[] hkdfExpand(
      SecretKey secretKey, FloeIv floeIv, FloeAad floeAad, FloePurpose purpose, int length) throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] encodedParams = parameterSpec.getEncodedParams();
    byte[] purposeBytes = purpose.generate();
    ByteBuffer info =
        ByteBuffer.allocate(
            encodedParams.length
                + floeIv.getBytes().length
                + purposeBytes.length
                + floeAad.getBytes().length);
    info.put(encodedParams);
    info.put(floeIv.getBytes());
    info.put(purposeBytes);
    info.put(floeAad.getBytes());
    return hkdfExpandInternal(parameterSpec.getHash(), secretKey, info.array(), length);
  }

  private byte[] hkdfExpandInternal(Hash hash, SecretKey prk, byte[] info, int len) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance(hash.getJceHmacName());
    mac.init(prk);
    mac.update(info);
    mac.update((byte) 1);
    byte[] bytes = mac.doFinal();
    if (bytes.length != len) {
      return Arrays.copyOf(bytes, len);
    }
    return bytes;
  }
}
