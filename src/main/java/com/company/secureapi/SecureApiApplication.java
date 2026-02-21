package com.company.secureapi;

import com.company.secureapi.user.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecureApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureApiApplication.class, args);
    }

    @Bean
    CommandLineRunner init(UserService userService){
        return args -> userService.createAdminIfNotExists();
    }
}
