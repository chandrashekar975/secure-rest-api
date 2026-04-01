package com.company.secureapi.controller;

import com.company.secureapi.audit.ApiLog;
import com.company.secureapi.audit.ApiLogRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/logs")
public class AuditController {

    private final ApiLogRepository apiLogRepository;

    public AuditController(ApiLogRepository apiLogRepository) {
        this.apiLogRepository = apiLogRepository;
    }

    // AUDITOR ONLY: View all activity logs
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping
    public List<ApiLog> viewAllLogs() {
        return apiLogRepository.findAllByOrderByTimestampDesc();
    }

    // AUDITOR ONLY: View suspicious activity (4xx/5xx status codes)
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/suspicious")
    public List<ApiLog> viewSuspiciousLogs() {
        return apiLogRepository.findByStatusCodeGreaterThanEqualOrderByTimestampDesc(400);
    }
}
