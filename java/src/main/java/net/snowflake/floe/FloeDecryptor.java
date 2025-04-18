package net.snowflake.floe;

/**
 * FLOE decryptor. Implementations of these classes are not thread safe.
 */
public interface FloeDecryptor extends AutoCloseable {
  /**
   * Processes given ciphertext to plaintext.
   * This function is to be used only with both terminal and non terminal segments.
   *
   * @param ciphertext ciphertext to be decrypted.
   * @return plaintext.
   */
  byte[] processSegment(byte[] ciphertext);

  /**
   * Processes given ciphertext to plaintext.
   * This function is to be used only with both terminal and non terminal segments.
   *
   * @param ciphertext ciphertext to be decrypted.
   * @param offset index of the first byte to process.
   * @param length how many bytes should be processed.
   * @return plaintext.
   */
  byte[] processSegment(byte[] ciphertext, int offset, int length);

  /**
   * Returns information if last segment was already processed.
   *
   * @return if last segment was already processed.
   */
  boolean isClosed();
}
