package net.snowflake.floe.stream;

import net.snowflake.floe.Floe;
import net.snowflake.floe.FloeEncryptor;
import net.snowflake.floe.FloeParameterSpec;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class FloeEncryptingInputStream extends InputStream {
  private final InputStream in;
  private final FloeParameterSpec parameterSpec;
  private final boolean writeHeader;
  private final FloeEncryptor encryptor;
  private final ByteBuffer headerBuf;
  private final ByteBuffer encryptedSegmentBuf;

  public FloeEncryptingInputStream(InputStream in, FloeParameterSpec parameterSpec, SecretKey secretKey, byte[] aad, boolean writeHeader) {
    this.in = in;
    this.parameterSpec = parameterSpec;
    this.writeHeader = writeHeader;
    this.encryptor = Floe.getInstance(parameterSpec).createEncryptor(secretKey, aad);
    this.headerBuf = ByteBuffer.wrap(encryptor.getHeader());
    this.encryptedSegmentBuf = ByteBuffer.allocate(parameterSpec.getEncryptedSegmentLength());
    this.encryptedSegmentBuf.position(parameterSpec.getEncryptedSegmentLength()); // meaning it needs to be filled
  }

  public byte[] getHeader() {
    return headerBuf.array().clone();
  }

  @Override
  public int read() throws IOException {
    if (writeHeader && headerBuf.hasRemaining()) {
      return headerBuf.get() & 0xFF;
    }
    if (encryptedSegmentBuf.hasRemaining()) {
      return encryptedSegmentBuf.get() & 0xFF;
    }
    if (encryptor.isClosed()) {
      return -1;
    }
    encryptedSegmentBuf.clear();
    byte[] plaintextSegment = new byte[parameterSpec.getPlainTextSegmentLength()];
    int readPlaintextBytes = in.read(plaintextSegment);
    byte[] ciphertextSegment;
    if (readPlaintextBytes == -1) {
      ciphertextSegment = encryptor.processSegment(new byte[0]);
    } else {
      ciphertextSegment = encryptor.processSegment(plaintextSegment, 0, readPlaintextBytes);
    }
    encryptedSegmentBuf.put(ciphertextSegment);
    encryptedSegmentBuf.flip();
    return encryptedSegmentBuf.get() & 0xFF;
  }

  @Override
  public int read(byte[] out, int off, int len) throws IOException {
    if (writeHeader && headerBuf.hasRemaining()) {
      int headerLengthToWrite = Math.min(headerBuf.remaining(), len);
      headerBuf.get(out, off, headerLengthToWrite);
      return headerLengthToWrite;
    }
    ByteBuffer outBuf = ByteBuffer.wrap(out, off, len);
    if (encryptedSegmentBuf.hasRemaining()) {
      byte[] remainingOfPreviousSegments = new byte[Math.min(encryptedSegmentBuf.remaining(), outBuf.remaining())];
      encryptedSegmentBuf.get(remainingOfPreviousSegments);
      outBuf.put(remainingOfPreviousSegments);
      if (encryptor.isClosed() || !outBuf.hasRemaining()) {
        return outBuf.position() - off;
      }
    }
    if (encryptor.isClosed()) {
      return -1;
    }
    while (outBuf.hasRemaining() && !encryptor.isClosed()) {
      byte[] plaintextSegment = new byte[parameterSpec.getPlainTextSegmentLength()];
      int read = in.read(plaintextSegment);
      byte[] ciphertextSegment;
      if (read == -1) {
        ciphertextSegment = encryptor.processSegment(new byte[0]);
      } else {
        ciphertextSegment = encryptor.processSegment(plaintextSegment, 0, read);
      }
      if (ciphertextSegment.length > outBuf.remaining()) {
        int remaining = outBuf.remaining();
        outBuf.put(ciphertextSegment, 0, remaining);
        if (!encryptedSegmentBuf.hasRemaining()) {
          encryptedSegmentBuf.clear();
        }
        encryptedSegmentBuf.put(ciphertextSegment, remaining, ciphertextSegment.length - remaining);
        encryptedSegmentBuf.flip();
      } else {
        outBuf.put(ciphertextSegment);
      }
    }
    return outBuf.position() - off;
  }

  @Override
  public void close() throws IOException {
    super.close();
    in.close();
    try {
      encryptor.close();
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  public boolean isClosed() {
    return encryptor.isClosed() && !encryptedSegmentBuf.hasRemaining();
  }
}
