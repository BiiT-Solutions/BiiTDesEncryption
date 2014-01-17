package com.biit.security.exceptions;

public class DESEncryptorException extends Exception {
	private static final long serialVersionUID = 5854639151680569625L;

	public DESEncryptorException(String text) {
		super(text);
	}

	public DESEncryptorException(String message, Exception e) {
		super(message, e);
	}
}
