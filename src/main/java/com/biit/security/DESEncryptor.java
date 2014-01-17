package com.biit.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;

import com.biit.security.exceptions.DESEncryptorException;

public class DESEncryptor {
	private static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
	private static Cipher encryptorCipher = null;
	private static Cipher decryptorCipher = null;
	private static final int ITERATION_COUNT = 10;
	private static String PASS_PHRASE = "aYxLpHZzuFammYJYaUbi";

	// 8-byte Salt
	private static byte[] salt = { (byte) 0xB2, (byte) 0x12, (byte) 0xD5, (byte) 0xB2, (byte) 0x44, (byte) 0x21,
			(byte) 0xC3, (byte) 0xC3 };

	/**
	 * Initialize variable.
	 * 
	 * @throws DESEncryptorException
	 */
	private static void initWithPassPhrase() throws DESEncryptorException {
		try {
			// create a user-chosen password that can be used with password-based encryption (PBE)
			// provide password, salt, iteration count for generating PBEKey of fixed-key-size PBE ciphers
			KeySpec keySpec = new PBEKeySpec(PASS_PHRASE.toCharArray(), salt, ITERATION_COUNT);

			// create a secret (symmetric) key using PBE with MD5 and DES
			SecretKey key = SecretKeyFactory.getInstance(DEFAULT_ALGORITHM).generateSecret(keySpec);

			// construct a parameter set for password-based encryption as defined in the PKCS #5 standard
			AlgorithmParameterSpec paramSpecification = new PBEParameterSpec(salt, ITERATION_COUNT);

			// Define the ciphers.
			encryptorCipher = Cipher.getInstance(key.getAlgorithm());
			decryptorCipher = Cipher.getInstance(key.getAlgorithm());

			// initialize the ciphers with the given key.
			encryptorCipher.init(Cipher.ENCRYPT_MODE, key, paramSpecification);
			decryptorCipher.init(Cipher.DECRYPT_MODE, key, paramSpecification);

		} catch (InvalidAlgorithmParameterException e) {
			throw new DESEncryptorException("Invalid Alogorithm Parameter:" + e.getMessage());
		} catch (InvalidKeySpecException e) {
			throw new DESEncryptorException("Invalid Key:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			throw new DESEncryptorException("No Such Algorithm:" + e.getMessage());
		} catch (NoSuchPaddingException e) {
			throw new DESEncryptorException("No Such Padding:" + e.getMessage());
		} catch (InvalidKeyException e) {
			throw new DESEncryptorException("Invalid Key:" + e.getMessage());
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
			byte[] utf8 = plainText.getBytes("UTF8");
			byte[] enc = encryptorCipher.doFinal(utf8);
			// encode to base64
			return Base64.encodeBase64URLSafeString(enc);
		} catch (UnsupportedEncodingException e) {
			throw new DESEncryptorException("Unsupported Encoding: " + e.getMessage());
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
			return new String(utf8, "UTF8");
		} catch (UnsupportedEncodingException e) {
			throw new DESEncryptorException("Unsupported Encoding: " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new DESEncryptorException("Illegal Block Size: " + e.getMessage());
		} catch (BadPaddingException e) {
			throw new DESEncryptorException("Bad Padding: " + e.getMessage());
		}

	}

}
