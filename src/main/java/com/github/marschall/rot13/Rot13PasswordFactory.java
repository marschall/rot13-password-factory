package com.github.marschall.rot13;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;

/**
 * The Elytron-provided password factory SPI implementation, which supports the
 * rot-13 password type.
 */
public final class Rot13PasswordFactory extends PasswordFactorySpi {

  @Override
  protected Password engineGeneratePassword(String algorithm, KeySpec keySpec) throws InvalidKeySpecException {

    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      if (keySpec instanceof HashPasswordSpec) {
        char[] password = new String(((HashPasswordSpec) keySpec).getDigest()).toCharArray();
        return new Rot13PasswordImpl(password);
      } else if (keySpec instanceof ClearPasswordSpec) {
        char[] password = ((ClearPasswordSpec) keySpec).getEncodedPassword();
        return new Rot13PasswordImpl(password);
      }
    }
    throw new InvalidKeySpecException("invalid algorithm: " + algorithm + " or key spec: " + keySpec.getClass());
  }

  @Override
  protected <S extends KeySpec> S engineGetKeySpec(String algorithm, Password password, Class<S> keySpecType)
      throws InvalidKeySpecException {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13) && password instanceof Rot13Password) {
      Rot13PasswordImpl rot13 = (Rot13PasswordImpl) password;
      return rot13.getKeySpec(keySpecType);
    }
    throw new InvalidKeySpecException("invalid algorithm: " + algorithm + " or key spec type: " + keySpecType);
  }

  @Override
  protected boolean engineIsTranslatablePassword(String algorithm, Password password) {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      return password instanceof Rot13PasswordImpl || password instanceof Rot13Password;
    }
    return false;
  }

  @Override
  protected Password engineTranslatePassword(String algorithm, Password password) throws InvalidKeyException {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      if (password instanceof Rot13PasswordImpl) {
        return password;
      }
      if (password instanceof Rot13Password) {
        return new Rot13PasswordImpl(((Rot13Password) password));
      }
    }
    throw new InvalidKeyException("unknown algorithm: " + algorithm + " or key spec: " + password.getClass());
  }

  @Override
  protected boolean engineVerify(String algorithm, Password password, char[] guess) throws InvalidKeyException {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      if (password instanceof Rot13PasswordImpl) {
        return ((Rot13PasswordImpl) password).verify(guess);
      }
    }
    throw new InvalidKeyException();
  }

  @Override
  protected boolean engineVerify(String algorithm, Password password, char[] guess, Charset hashCharset)
      throws InvalidKeyException {
    return this.engineVerify(algorithm, password, guess);
  }

  @Override
  protected <S extends KeySpec> boolean engineConvertibleToKeySpec(String algorithm, Password password,
      Class<S> keySpecType) {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      if (password instanceof Rot13PasswordImpl) {
        return ((Rot13PasswordImpl) password).convertibleTo(keySpecType);
      }
    }
    return false;
  }

  @Override
  protected Password engineTransform(String algorithm, Password password, AlgorithmParameterSpec parameterSpec)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (algorithm.equals(Rot13Password.ALGORITHM_ROT_13)) {
      throw new InvalidAlgorithmParameterException();
    }
    throw new InvalidKeyException();
  }

}
