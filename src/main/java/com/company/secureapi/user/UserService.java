package com.company.secureapi.user;

import com.company.secureapi.auth.RegisterRequest;
import com.company.secureapi.exception.DuplicateEmailException;
import com.company.secureapi.exception.DuplicateUsernameException;
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
}
