package com.company.secureapi.exception;

public class DuplicateEmailException extends RuntimeException {
    public DuplicateEmailException() {
        super("Email already exists");
    }
}
