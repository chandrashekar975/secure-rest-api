package com.company.secureapi.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auditor")
public class AuditorController {

    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/logs")
    public String viewLogs() {
        return "Audit Logs";
    }
}