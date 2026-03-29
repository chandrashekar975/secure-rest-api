package com.company.secureapi.auth;

public class LoginResponse {

    private final String token;
    private final String username;
    private final String role;
    private final String refreshToken;

    public LoginResponse(String token, String username, String role, String refreshToken) {
        this.token = token;
        this.username = username;
        this.role = role;
        this.refreshToken = refreshToken;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}