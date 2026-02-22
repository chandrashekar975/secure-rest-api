package com.company.secureapi.user;

import com.company.secureapi.auth.RegisterRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.dao.DataIntegrityViolationException;
import java.time.LocalDateTime;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${ADMIN_PASSWORD}")
    private String adminPassword;

    public UserService(UserRepository userRepository,PasswordEncoder passwordEncoder){
        this.userRepository=userRepository;
        this.passwordEncoder=passwordEncoder;
    }

    public void createAdminIfNotExists(){
        if (!userRepository.existsByRole(Role.ADMIN)){

            User admin=new User(
                    "admin",
                    "admin@company.com",
                    passwordEncoder.encode(adminPassword),
                    Role.ADMIN,
                    AccountStatus.ACTIVE,
                    LocalDateTime.now()
            );

            userRepository.save(admin);
        }
    }

    @Transactional
    public User createEmployee(RegisterRequest request){
        String normalizedUsername = request.getUsername().trim().toLowerCase();
        String normalizedEmail = request.getEmail().trim().toLowerCase();

        if (userRepository.existsByUsername(normalizedUsername)) {
            throw new DuplicateResourceException("Username already exists");
        }

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new DuplicateResourceException("Email already exists");
        }

        try {
            User user = new User(
                    normalizedUsername,
                    normalizedEmail,
                    passwordEncoder.encode(request.getPassword()),
                    Role.EMPLOYEE,
                    AccountStatus.ACTIVE,
                    java.time.LocalDateTime.now()
            );

            return userRepository.save(user);

        } catch (DataIntegrityViolationException ex) {
            throw new DuplicateResourceException("Username or Email already exists");
        }
    }
}
