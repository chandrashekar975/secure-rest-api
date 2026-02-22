package com.company.secureapi.auth;

public class LoginResponse {

    private final String message;
    private final String username;
    private final String role;

    public LoginResponse(String message, String username, String role) {
        this.message = message;
        this.username = username;
        this.role = role;
    }

    public String getMessage() {
        return message;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }
}
