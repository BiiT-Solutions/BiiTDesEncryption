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

import org.testng.Assert;
import org.testng.annotations.Test;

import com.biit.security.exceptions.DESEncryptorException;

@Test(groups = { "DESGroup" })
public class DESEncryptorTest {

	private void encryptAndDecrypt(String plainText) throws DESEncryptorException {
		// Encrypt text.
		String encryptedText = DESEncryptor.encrypt(plainText);
		// Have modified the text.
        Assert.assertNotEquals(encryptedText, plainText);
		// Decrypt text.
		String decryptedText = DESEncryptor.decrypt(encryptedText);
		// Decrypted text is the same as the original.
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
