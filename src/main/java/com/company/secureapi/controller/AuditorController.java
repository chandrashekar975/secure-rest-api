package com.company.secureapi.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.company.secureapi.audit.ApiLog;
import com.company.secureapi.audit.ApiLogRepository;
import java.util.List;

@RestController
@RequestMapping("/api/auditor")
public class AuditorController {

    private final ApiLogRepository apiLogRepository;

    public AuditorController(ApiLogRepository apiLogRepository) {
        this.apiLogRepository = apiLogRepository;
    }

    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/logs")
    public List<ApiLog> viewLogs() {
        return apiLogRepository.findAllByOrderByTimestampDesc();
    }
}