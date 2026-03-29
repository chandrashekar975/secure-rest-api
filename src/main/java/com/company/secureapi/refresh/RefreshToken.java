package com.company.secureapi.refresh;

import com.company.secureapi.user.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    private User user;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiry;

    public RefreshToken() {}

    public RefreshToken(User user, String token, LocalDateTime expiry) {
        this.user = user;
        this.token = token;
        this.expiry = expiry;
    }

    public User getUser() { return user; }
    public String getToken() { return token; }
    public LocalDateTime getExpiry() { return expiry; }
}