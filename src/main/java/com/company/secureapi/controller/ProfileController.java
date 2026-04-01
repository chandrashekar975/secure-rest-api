package com.company.secureapi.controller;

import com.company.secureapi.user.User;
import com.company.secureapi.user.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/profile")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        User user = userService.getUserByUsername(authentication.getName());
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "role", user.getRole().name(),
                "accountStatus", user.getAccountStatus().name(),
                "createdAt", user.getCreatedAt().toString()
        ));
    }

    @PutMapping
    public ResponseEntity<Map<String, Object>> updateProfile(
            Authentication authentication,
            @RequestBody Map<String, String> updates) {

        User user = userService.updateProfile(
                authentication.getName(),
                updates.get("email")
        );

        return ResponseEntity.ok(Map.of(
                "message", "Profile updated successfully",
                "username", user.getUsername(),
                "email", user.getEmail()
        ));
    }
}
