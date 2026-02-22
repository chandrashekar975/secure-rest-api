package com.company.secureapi.user;

import com.company.secureapi.auth.LoginRequest;
import com.company.secureapi.auth.LoginResponse;
import com.company.secureapi.auth.RegisterRequest;
import com.company.secureapi.exception.DuplicateEmailException;
import com.company.secureapi.exception.DuplicateUsernameException;
import com.company.secureapi.exception.InvalidCredentialsException;
import com.company.secureapi.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Value("${ADMIN_PASSWORD}")
    private String adminPassword;

    private final JwtService jwtService;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public void createAdminIfNotExists() {

        if (!userRepository.existsByRole(Role.ADMIN)) {

            if (adminPassword == null || adminPassword.isBlank()) {
                throw new IllegalStateException("ADMIN_PASSWORD environment variable not set");
            }

            User admin = new User(
                    "admin",
                    "admin@company.com",
                    passwordEncoder.encode(adminPassword),
                    Role.ADMIN,
                    AccountStatus.ACTIVE
            );

            userRepository.save(admin);
        }
    }

    public User createEmployee(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException();
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException();
        }

        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                Role.EMPLOYEE,
                AccountStatus.ACTIVE
        );

        return userRepository.save(user);
    }

    public LoginResponse authenticate(LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(InvalidCredentialsException::new);

        if (user.getAccountStatus() != AccountStatus.ACTIVE) {
            throw new InvalidCredentialsException();
        }

        String token = jwtService.generateToken(
                user.getUsername(),
                user.getRole().name()
        );

        return new LoginResponse(
                token,
                user.getUsername(),
                user.getRole().name()
        );
    }
}