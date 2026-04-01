package com.company.secureapi.controller;

import com.company.secureapi.audit.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/logs")
public class AuditController {

    private final ApiLogRepository apiLogRepository;
    private final SecurityAlertRepository securityAlertRepository;

    public AuditController(ApiLogRepository apiLogRepository,
                           SecurityAlertRepository securityAlertRepository) {
        this.apiLogRepository = apiLogRepository;
        this.securityAlertRepository = securityAlertRepository;
    }

    // ===== LOG ENDPOINTS =====

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

    // ===== ALERT ENDPOINTS =====

    // AUDITOR ONLY: View all security alerts
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/alerts")
    public List<SecurityAlert> viewAllAlerts() {
        return securityAlertRepository.findAllByOrderByCreatedAtDesc();
    }

    // AUDITOR ONLY: View only active (unresolved) alerts
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/alerts/active")
    public List<SecurityAlert> viewActiveAlerts() {
        return securityAlertRepository.findByResolvedFalseOrderByCreatedAtDesc();
    }

    // AUDITOR ONLY: Get count of active alerts
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/alerts/count")
    public ResponseEntity<Map<String, Long>> getActiveAlertCount() {
        long count = securityAlertRepository.countByResolvedFalse();
        return ResponseEntity.ok(Map.of("activeAlerts", count));
    }

    // AUDITOR ONLY: Resolve (dismiss) an alert
    @PreAuthorize("hasRole('AUDITOR')")
    @PutMapping("/alerts/{id}/resolve")
    public ResponseEntity<Map<String, String>> resolveAlert(@PathVariable Long id) {
        SecurityAlert alert = securityAlertRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Alert not found with id: " + id));

        alert.setResolved(true);
        alert.setResolvedAt(LocalDateTime.now());
        securityAlertRepository.save(alert);

        return ResponseEntity.ok(Map.of("message", "Alert resolved successfully"));
    }

    // ===== STATS ENDPOINT =====

    // AUDITOR ONLY: Get security statistics
    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        LocalDateTime last24h = LocalDateTime.now().minusHours(24);

        long totalRequests = apiLogRepository.count();
        long recentRequests = apiLogRepository.countByTimestampAfter(last24h);
        long activeAlerts = securityAlertRepository.countByResolvedFalse();
        long totalAlerts = securityAlertRepository.count();

        return ResponseEntity.ok(Map.of(
                "totalRequests", totalRequests,
                "recentRequests", recentRequests,
                "activeAlerts", activeAlerts,
                "totalAlerts", totalAlerts
        ));
    }
}
