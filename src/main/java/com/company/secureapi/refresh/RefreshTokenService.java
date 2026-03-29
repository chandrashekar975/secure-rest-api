package com.company.secureapi.refresh;

import com.company.secureapi.user.User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    public RefreshTokenService(RefreshTokenRepository repository) {
        this.repository = repository;
    }

    public RefreshToken createRefreshToken(User user) {

        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken(
                user,
                token,
                LocalDateTime.now().plusDays(7)
        );

        return repository.save(refreshToken);
    }

    public RefreshToken validateToken(String token) {

        RefreshToken rt = repository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (rt.getExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        return rt;
    }

    public void deleteByUser(User user) {
        repository.deleteByUserId(user.getId());
    }
}