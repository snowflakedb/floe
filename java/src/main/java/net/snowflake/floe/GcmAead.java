package net.snowflake.floe;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

// This class is not thread safe!
// But as long as it is used only for FLOE, it is fine, as FLOE instance keeps its own instance of
// GCM.
class GcmAead implements AeadProvider {
  private final Cipher cipher;
  private final int tagLengthInBits;

  public GcmAead(int tagLengthInBytes) {
    try {
      cipher = Cipher.getInstance("AES/GCM/NoPadding");
      this.tagLengthInBits = tagLengthInBytes * 8;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @Override
  public byte[] encrypt(AeadKey key, AeadIv iv, AeadAad aad, byte[] plaintext)
      throws GeneralSecurityException {
    return process(key, iv, aad, plaintext, Cipher.ENCRYPT_MODE);
  }

  @Override
  public byte[] decrypt(AeadKey key, AeadIv iv, AeadAad aad, byte[] ciphertext)
      throws GeneralSecurityException {
    return process(key, iv, aad, ciphertext, Cipher.DECRYPT_MODE);
  }

  private byte[] process(AeadKey key, AeadIv iv, AeadAad aad, byte[] plaintext, int opmode)
      throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException {
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLengthInBits, iv.getBytes());
    cipher.init(opmode, key.getKey(), gcmParameterSpec);
    if (aad != null) {
      cipher.updateAAD(aad.getBytes());
    }
    return cipher.doFinal(plaintext);
  }
}
