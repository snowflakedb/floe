package net.snowflake.floe.aead;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

// This class is not thread safe!
// But as long as it is used only for FLOE, it is fine, as FLOE instance keeps its own instance of
// GCM.
public class Gcm implements AeadProvider {
  private final Cipher cipher;
  private final int tagLengthInBits;

  public Gcm(int tagLengthInBytes) {
    try {
      cipher = Cipher.getInstance("AES/GCM/NoPadding");
      this.tagLengthInBits = tagLengthInBytes * 8;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  @Override
  public byte[] encrypt(SecretKey key, byte[] iv, byte[] aad, byte[] plaintext)
      throws GeneralSecurityException {
    return process(key, iv, aad, plaintext, Cipher.ENCRYPT_MODE);
  }

  @Override
  public byte[] decrypt(SecretKey key, byte[] iv, byte[] aad, byte[] ciphertext)
      throws GeneralSecurityException {
    return process(key, iv, aad, ciphertext, Cipher.DECRYPT_MODE);
  }

  private byte[] process(SecretKey key, byte[] iv, byte[] aad, byte[] plaintext, int opmode)
      throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException {
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLengthInBits, iv);
    cipher.init(opmode, key, gcmParameterSpec);
    if (aad != null) {
      cipher.updateAAD(aad);
    }
    return cipher.doFinal(plaintext);
  }
}
