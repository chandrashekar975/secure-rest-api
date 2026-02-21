package com.company.secureapi.user;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
        if(userRepository.count()==0){

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
}
