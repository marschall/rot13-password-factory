package com.github.marschall.rot13;

import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;

/**
 * ROT-13 encrypted password.
 */
public interface Rot13Password extends OneWayPassword {

  /**
   * The algorithm name "rot-13".
   */
  String ALGORITHM_ROT_13 = "rot-13";

  /**
   * Get the password characters.
   *
   * @return the password characters
   */
  char[] getPassword();

  /**
   * Creates and returns a copy of this {@link Password}.
   *
   * @return a copy of this {@link Password}.
   */
  Rot13Password clone();

}
