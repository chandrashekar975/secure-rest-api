package com.company.secureapi.auth;

import com.company.secureapi.refresh.RefreshToken;
import com.company.secureapi.refresh.RefreshTokenService;
import com.company.secureapi.security.jwt.JwtService;
import com.company.secureapi.user.User;
import com.company.secureapi.user.UserService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    public AuthController(UserService userService,
                          RefreshTokenService refreshTokenService,
                          JwtService jwtService) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        var user = userService.createEmployee(request);

        return new RegisterResponse(
                user.getUsername(),
                user.getEmail(),
                user.getRole().name()
        );
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return userService.authenticate(request);
    }

    // 🔥 REFRESH API
    @PostMapping("/refresh")
    public LoginResponse refresh(@RequestParam String refreshToken) {

        RefreshToken rt = refreshTokenService.validateToken(refreshToken);
        User user = rt.getUser();

        String newAccessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole().name()
        );

        return new LoginResponse(
                newAccessToken,
                user.getUsername(),
                user.getRole().name(),
                refreshToken
        );
    }

    // 🔥 LOGOUT API
    @PostMapping("/logout")
    public String logout(@RequestParam String refreshToken) {

        RefreshToken rt = refreshTokenService.validateToken(refreshToken);
        refreshTokenService.deleteByUser(rt.getUser());

        return "Logged out successfully";
    }
}