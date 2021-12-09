package com.github.marschall.rot13;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;

/**
 * ROT-13 encrypted credential type implementation.
 */
final class Rot13PasswordImpl implements Rot13Password {

  private final char[] password;

  Rot13PasswordImpl(char[] password) {
    this.password = password;
  }

  Rot13PasswordImpl(Rot13Password rot13Password) {
    this.password = rot13Password.getPassword();
  }

  @Override
  public Rot13Password clone() {
    return new Rot13PasswordImpl(this.password.clone());
  }

  @Override
  public char[] getPassword() throws IllegalStateException {
    return this.password;
  }

  @Override
  public String getAlgorithm() {
    return ALGORITHM_ROT_13;
  }

  boolean verify(char[] guess) {
    int passwordLength = this.password.length;
    int guessLength = guess.length;

    if (guessLength == 0) {
      return passwordLength == 0;
    }

    int result = passwordLength - guessLength;

    // time-constant comparison
    for (int i = 0; i < passwordLength; i++) {
      // If i >= passwordLength, guessIndex is 0; otherwise, i.
      int guessIndex = ((i - guessLength) >>> 31) * i;
      char guessRot13 = rot13(guess[guessIndex]);
      result |= this.password[i] ^ guessRot13;
    }
    return result == 0;
  }

  private static char rot13(char c) {
    if (c >= 'a' && c <= 'm') {
      return (char) (c + 13);
    } else if (c >= 'A' && c <= 'M') {
      return (char) (c + 13);
    } else if (c >= 'n' && c <= 'z') {
      return (char) (c - 13);
    } else if (c >= 'N' && c <= 'Z') {
      return (char) (c - 13);
    }
    return c;
  }

  @Override
  public String getFormat() {
    return null;
  }

  @Override
  public byte[] getEncoded() {
    return null;
  }

  <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
    if (keySpecType.isAssignableFrom(HashPasswordSpec.class)) {
      return keySpecType.cast(new HashPasswordSpec(new String(this.password).getBytes()));
    }
    if (keySpecType.isAssignableFrom(ClearPasswordSpec.class)) {
      return keySpecType.cast(new ClearPasswordSpec(this.password.clone()));
    }
    throw new InvalidKeySpecException();
  }

  <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
    return keySpecType.isAssignableFrom(HashPasswordSpec.class)
        || keySpecType.isAssignableFrom(ClearPasswordSpec.class);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.password);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Rot13PasswordImpl)) {
      return false;
    }
    Rot13PasswordImpl other = (Rot13PasswordImpl) obj;
    return Arrays.equals(this.password, other.password);
  }

}
