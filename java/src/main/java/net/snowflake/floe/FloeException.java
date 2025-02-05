package net.snowflake.floe;

public class FloeException extends Exception {
  public FloeException(String message, Throwable cause) {
    super(message, cause);
  }

  public FloeException(Throwable cause) {
    super(cause);
  }
}
