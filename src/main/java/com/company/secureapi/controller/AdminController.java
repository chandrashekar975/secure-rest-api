package com.company.secureapi.controller;

import com.company.secureapi.user.User;
import com.company.secureapi.user.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    // ADMIN ONLY: View all users
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    // ADMIN ONLY: Delete a user
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    // ADMIN ONLY: Block a user account
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/block/{id}")
    public ResponseEntity<Map<String, Object>> blockUser(@PathVariable Long id) {
        User user = userService.blockUser(id);
        return ResponseEntity.ok(Map.of(
                "message", "User blocked successfully",
                "username", user.getUsername(),
                "accountStatus", user.getAccountStatus().name()
        ));
    }
}