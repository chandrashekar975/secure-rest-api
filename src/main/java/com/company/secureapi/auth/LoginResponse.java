package com.company.secureapi.auth;

public class LoginResponse {

    private final String accessToken;
    private final String username;
    private final String role;
    private final String refreshToken;

    public LoginResponse(String accessToken, String username, String role, String refreshToken) {
        this.accessToken = accessToken;
        this.username = username;
        this.role = role;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
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