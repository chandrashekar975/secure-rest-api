package com.company.secureapi.user;

import com.company.secureapi.auth.LoginResponse;
import com.company.secureapi.auth.LoginRequest;
import com.company.secureapi.auth.RegisterRequest;
import com.company.secureapi.exception.DuplicateEmailException;
import com.company.secureapi.exception.DuplicateUsernameException;
import com.company.secureapi.exception.InvalidCredentialsException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
                    AccountStatus.ACTIVE
            );

            userRepository.save(admin);
        }
    }

    public User createEmployee(RegisterRequest request){

        if(userRepository.existsByUsername(request.getUsername())){
            throw new DuplicateUsernameException();
        }

        if(userRepository.existsByEmail(request.getEmail())){
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

    public LoginResponse authenticate(LoginRequest request){
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(InvalidCredentialsException::new);

        boolean passwordMatches = passwordEncoder.matches(request.getPassword(), user.getPassword());
        if (!passwordMatches || user.getAccountStatus() != AccountStatus.ACTIVE) {
            throw new InvalidCredentialsException();
        }

        return new LoginResponse(
                "Login successful",
                user.getUsername(),
                user.getRole().name()
        );
    }
}
