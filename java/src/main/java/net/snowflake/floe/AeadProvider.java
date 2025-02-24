package net.snowflake.floe;

import java.security.GeneralSecurityException;

// Consideration for implementations:
// 1. Implementations do not have to be thread safe, they are used in FLOE in a thread safe manner
// (FLOE encryptor and decryptor create and keep their own instances).
// 2. Authentication tag appended to the ciphertext:
// a) For encrypt function - auth tag is returned with ciphertext.
// b) For decrypt function - auth tag is passed with ciphertext.
public interface AeadProvider {
  byte[] encrypt(AeadKey key, AeadIv iv, AeadAad aad, byte[] plaintext)
      throws GeneralSecurityException;

  byte[] decrypt(AeadKey key, AeadIv iv, AeadAad aad, byte[] ciphertext)
      throws GeneralSecurityException;
}
