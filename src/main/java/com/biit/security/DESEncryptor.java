package com.biit.security;

/*-
 * #%L
 * DES Encryption Utils
 * %%
 * Copyright (C) 2014 - 2025 BiiT Sourcing Solutions S.L.
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */

import com.biit.security.exceptions.DESEncryptorException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public final class DESEncryptor {
    private static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
    private static Cipher encryptorCipher = null;
    private static Cipher decryptorCipher = null;
    private static final int ITERATION_COUNT = 10;
    private static String pass = "aYxLpHZzuFammYJYaUbi";

    // 8-byte Salt
    private static final byte[] SALT = {(byte) 0xB2, (byte) 0x12, (byte) 0xD5, (byte) 0xB2, (byte) 0x44, (byte) 0x21,
            (byte) 0xC3, (byte) 0xC3};

    private DESEncryptor() {

    }

    /**
     * Initialize variable.
     *
     * @throws DESEncryptorException
     */
    private static void initWithPassPhrase() throws DESEncryptorException {
        try {
            // create a user-chosen password that can be used with password-based encryption (PBE)
            // provide password, salt, iteration count for generating PBEKey of fixed-key-size PBE ciphers
            KeySpec keySpec = new PBEKeySpec(pass.toCharArray(), SALT, ITERATION_COUNT);

            // create a secret (symmetric) key using PBE with MD5 and DES
            SecretKey key = SecretKeyFactory.getInstance(DEFAULT_ALGORITHM).generateSecret(keySpec);

            // construct a parameter set for password-based encryption as defined in the PKCS #5 standard
            AlgorithmParameterSpec paramSpecification = new PBEParameterSpec(SALT, ITERATION_COUNT);

            // Define the ciphers.
            encryptorCipher = Cipher.getInstance(key.getAlgorithm());
            decryptorCipher = Cipher.getInstance(key.getAlgorithm());

            // initialize the ciphers with the given key.
            encryptorCipher.init(Cipher.ENCRYPT_MODE, key, paramSpecification);
            decryptorCipher.init(Cipher.DECRYPT_MODE, key, paramSpecification);

        } catch (InvalidAlgorithmParameterException e) {
            throw new DESEncryptorException("Invalid Alogorithm Parameter:" + e.getMessage());
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            throw new DESEncryptorException("Invalid Key:" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new DESEncryptorException("No Such Algorithm:" + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new DESEncryptorException("No Such Padding:" + e.getMessage());
        }
    }

    /**
     * Convert a plain text to a string with the encrypted result. Encode the string into a sequence of bytes using the
     * named charset storing the result into a new byte array.
     *
     * @param plainText
     * @return
     * @throws DESEncryptorException
     */
    public static String encrypt(String plainText) throws DESEncryptorException {
        try {
            if (encryptorCipher == null) {
                initWithPassPhrase();
            }
            byte[] utf8 = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] enc = encryptorCipher.doFinal(utf8);
            // encode to base64
            return Base64.encodeBase64URLSafeString(enc);
        } catch (IllegalBlockSizeException e) {
            throw new DESEncryptorException("Illegal Block Size: " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new DESEncryptorException("Bad Padding: " + e.getMessage());
        }

    }

    /**
     * Decrypt a codified text to a plain text string.
     *
     * @param codifiedText
     * @return
     * @throws DESEncryptorException
     */
    public static String decrypt(String codifiedText) throws DESEncryptorException {
        try {
            if (decryptorCipher == null) {
                initWithPassPhrase();
            }
            // decode with base64 to get bytes
            byte[] dec = Base64.decodeBase64(codifiedText);
            byte[] utf8 = decryptorCipher.doFinal(dec);
            // create new string based on the specified charset
            return new String(utf8, StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException e) {
            throw new DESEncryptorException("Illegal Block Size: " + e.getMessage());
        } catch (BadPaddingException e) {
            throw new DESEncryptorException("Bad Padding: " + e.getMessage());
        }

    }

}
