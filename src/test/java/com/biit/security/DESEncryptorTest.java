package com.biit.security;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.biit.security.exceptions.DESEncryptorException;

@Test(groups = { "DESGroup" })
public class DESEncryptorTest {

	private void encryptAndDecrypt(String plainText) throws DESEncryptorException {
		// Encrypt text.
		String encryptedText = DESEncryptor.encrypt(plainText);
		// Have modified the text.
		Assert.assertFalse(plainText.equals(encryptedText));
		// Decrypt text.
		String decryptedText = DESEncryptor.decrypt(encryptedText);
		// Decrypted text is the same than the original.
		Assert.assertEquals(decryptedText, plainText);
	}

	@Test
	public void encryptAndDecrypt() throws DESEncryptorException {
		encryptAndDecrypt("Text to encrypt.");
	}

	@Test
	public void encryptAndDecryptSpecialChars() throws DESEncryptorException {
		encryptAndDecrypt("ñ+?¿7()%&$·");
	}

}
