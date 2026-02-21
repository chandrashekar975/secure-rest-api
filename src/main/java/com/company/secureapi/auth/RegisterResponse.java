package com.company.secureapi.auth;

public class RegisterResponse {

    private String username;
    private String email;
    private String role;

    public RegisterResponse(String username, String email, String role) {
        this.username = username;
        this.email = email;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getEmail() {
        return email;
    }
}