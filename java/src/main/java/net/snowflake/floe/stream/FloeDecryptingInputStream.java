package net.snowflake.floe.stream;

import net.snowflake.floe.Floe;
import net.snowflake.floe.FloeDecryptor;
import net.snowflake.floe.FloeParameterSpec;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class FloeDecryptingInputStream extends InputStream {
  private final InputStream in;
  private final FloeParameterSpec parameterSpec;
  private final FloeDecryptor decryptor;
  private final ByteBuffer plaintextSegmentBuf;

  public FloeDecryptingInputStream(InputStream in, FloeParameterSpec parameterSpec, SecretKey secretKey, byte[] aad) throws IOException {
    this(in, parameterSpec, secretKey, aad, null);
  }

  public FloeDecryptingInputStream(InputStream in, FloeParameterSpec parameterSpec, SecretKey secretKey, byte[] aad, byte[] header) throws IOException {
    this.in = in;
    this.parameterSpec = parameterSpec;
    if (header == null) {
      header = new byte[parameterSpec.getHeaderSize()];
      in.read(header);
    }
    this.decryptor = Floe.getInstance(parameterSpec).createDecryptor(secretKey, aad, header);
    this.plaintextSegmentBuf = ByteBuffer.allocate(parameterSpec.getPlainTextSegmentLength());
    this.plaintextSegmentBuf.position(parameterSpec.getPlainTextSegmentLength()); // meaning it needs to be filled
  }

  @Override
  public int read() throws IOException {
    if (plaintextSegmentBuf.hasRemaining()) {
      return plaintextSegmentBuf.get() & 0xFF;
    }
    if (decryptor.isClosed()) {
      return -1;
    }
    byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
    int readPlaintextBytes = in.read(ciphertextSegment);
    byte[] plaintextSegment = decryptor.processSegment(ciphertextSegment, 0, readPlaintextBytes);
    if (plaintextSegment.length == 0) {
      return -1;
    }
    plaintextSegmentBuf.rewind();
    plaintextSegmentBuf.put(plaintextSegment);
    plaintextSegmentBuf.flip();
    return plaintextSegmentBuf.get() & 0xFF;
  }

  @Override
  public int read(byte[] out, int off, int len) throws IOException {
    ByteBuffer outBuf = ByteBuffer.wrap(out, off, len);
    if (plaintextSegmentBuf.hasRemaining()) {
      byte[] remainingOfPreviousSegments = new byte[Math.min(plaintextSegmentBuf.remaining(), outBuf.remaining())];
      plaintextSegmentBuf.get(remainingOfPreviousSegments);
      outBuf.put(remainingOfPreviousSegments);
      if (decryptor.isClosed() || !outBuf.hasRemaining()) {
        return outBuf.position() - off;
      }
    }
    if (decryptor.isClosed()) {
      return -1;
    }
    while (outBuf.hasRemaining() && !decryptor.isClosed()) {
      byte[] ciphertextSegment = new byte[parameterSpec.getEncryptedSegmentLength()];
      int read = in.read(ciphertextSegment);
      byte[] plaintextSegment = decryptor.processSegment(ciphertextSegment, 0, read);
      if (plaintextSegment.length > outBuf.remaining()) {
        int remaining = outBuf.remaining();
        outBuf.put(plaintextSegment, 0, remaining);
        if (!plaintextSegmentBuf.hasRemaining()) {
          plaintextSegmentBuf.clear();
        }
        plaintextSegmentBuf.put(plaintextSegment, remaining, plaintextSegment.length - remaining);
        plaintextSegmentBuf.flip();
      } else {
        outBuf.put(plaintextSegment);
      }
    }
    return outBuf.position() - off;
  }

  public boolean isClosed() {
    return decryptor.isClosed() && !plaintextSegmentBuf.hasRemaining();
  }

  @Override
  public void close() throws IOException {
    super.close();
    in.close();
    try {
      decryptor.close();
    } catch (Exception e) {
      throw new IOException(e);
    }
  }
}
