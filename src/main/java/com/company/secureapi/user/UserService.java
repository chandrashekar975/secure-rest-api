package com.company.secureapi.user;

import com.company.secureapi.audit.AuditRuleEngine;
import com.company.secureapi.auth.LoginRequest;
import com.company.secureapi.auth.LoginResponse;
import com.company.secureapi.auth.RegisterRequest;
import com.company.secureapi.exception.DuplicateEmailException;
import com.company.secureapi.exception.DuplicateUsernameException;
import com.company.secureapi.exception.InvalidCredentialsException;
import com.company.secureapi.refresh.RefreshToken;
import com.company.secureapi.refresh.RefreshTokenRepository;
import com.company.secureapi.refresh.RefreshTokenService;
import com.company.secureapi.security.jwt.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final AuditRuleEngine auditRuleEngine;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       RefreshTokenService refreshTokenService,
                       RefreshTokenRepository refreshTokenRepository,
                       AuditRuleEngine auditRuleEngine) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditRuleEngine = auditRuleEngine;
    }

    public void createAdminIfNotExists() {
        if (!userRepository.existsByRole(Role.ADMIN)) {
            User admin = new User(
                    "admin",
                    "admin@company.com",
                    passwordEncoder.encode("Admin@123"),
                    Role.ADMIN,
                    AccountStatus.ACTIVE
            );
            userRepository.save(admin);
            System.out.println("=== Default ADMIN user created (username: admin, password: Admin@123) ===");
        }
    }

    public User createUser(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException();
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException();
        }

        // Determine role from request — default to EMPLOYEE
        Role role = Role.EMPLOYEE;
        if (request.getRole() != null && !request.getRole().isBlank()) {
            try {
                Role requestedRole = Role.valueOf(request.getRole().toUpperCase());
                // Only allow EMPLOYEE and AUDITOR via registration
                // ADMIN can only be seeded
                if (requestedRole == Role.EMPLOYEE || requestedRole == Role.AUDITOR) {
                    role = requestedRole;
                }
            } catch (IllegalArgumentException ignored) {
                // Invalid role string — use default EMPLOYEE
            }
        }

        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                role,
                AccountStatus.ACTIVE
        );

        return userRepository.save(user);
    }

    @Transactional
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
            // RULE 4: Raise alert when blocked user tries to login
            auditRuleEngine.raiseBlockedUserAlert(
                    user.getUsername(),
                    "Account status: " + user.getAccountStatus().name()
            );
            throw new InvalidCredentialsException();
        }

        // Delete old refresh token
        refreshTokenRepository.deleteByUser(user);

        // Generate access token
        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole().name()
        );

        // Generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return new LoginResponse(
                accessToken,
                user.getUsername(),
                user.getRole().name(),
                refreshToken.getToken()
        );
    }

    // --- Profile Methods ---

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Transactional
    public User updateProfile(String username, String newEmail) {
        User user = getUserByUsername(username);
        if (newEmail != null && !newEmail.isBlank() && !newEmail.equals(user.getEmail())) {
            if (userRepository.existsByEmail(newEmail)) {
                throw new DuplicateEmailException();
            }
            user.setEmail(newEmail);
        }
        return userRepository.save(user);
    }

    // --- Admin Methods ---

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("User not found with id: " + id);
        }
        // Also delete refresh tokens for the user
        refreshTokenRepository.deleteByUserId(id);
        userRepository.deleteById(id);
    }

    @Transactional
    public User blockUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
        user.setAccountStatus(AccountStatus.BLOCKED);
        return userRepository.save(user);
    }
}