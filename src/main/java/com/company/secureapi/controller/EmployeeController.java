package com.company.secureapi.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/employee")
public class EmployeeController {

    @PreAuthorize("hasRole('EMPLOYEE')")
    @GetMapping("/profile")
    public String getProfile() {
        return "Employee Profile";
    }
}