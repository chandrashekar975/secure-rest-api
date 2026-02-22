package com.company.secureapi.exception;

public class DuplicateUsernameException extends RuntimeException {
    public DuplicateUsernameException() {
        super("Username already exists");
    }
}
