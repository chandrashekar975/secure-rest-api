package com.company.secureapi.audit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Audit Rule Engine — evaluates security rules after every API request.
 *
 * Rules:
 * 1. BRUTE_FORCE:          5+ failed logins (401) from same IP in 5 minutes → CRITICAL
 * 2. PRIVILEGE_ESCALATION: 5+ forbidden (403) from same user in 5 minutes → HIGH
 * 3. RAPID_ACCESS:         50+ requests from same IP in 1 minute → MEDIUM
 * 4. BLOCKED_USER_ACCESS:  Triggered externally when a blocked user tries to login → HIGH
 */
@Service
public class AuditRuleEngine {

    private final ApiLogRepository logRepository;
    private final SecurityAlertRepository alertRepository;

    public AuditRuleEngine(ApiLogRepository logRepository,
                           SecurityAlertRepository alertRepository) {
        this.logRepository = logRepository;
        this.alertRepository = alertRepository;
    }

    /**
     * Evaluate all rules against the most recently saved log entry.
     * Called by ApiLoggingFilter after each request is logged.
     */
    public void evaluate(ApiLog log) {
        try {
            checkBruteForce(log);
            checkPrivilegeEscalation(log);
            checkRapidAccess(log);
        } catch (Exception e) {
            // Rule evaluation should never break the request pipeline
            System.err.println("AuditRuleEngine error: " + e.getMessage());
        }
    }

    /**
     * Rule 1: Brute Force Detection
     * IF 5+ requests with status 401 from same IP in last 5 minutes
     * AND no unresolved BRUTE_FORCE alert exists for this IP
     * THEN create CRITICAL alert
     */
    private void checkBruteForce(ApiLog log) {
        if (log.getStatusCode() != 401) return;

        String ip = log.getIpAddress();
        LocalDateTime fiveMinAgo = LocalDateTime.now().minusMinutes(5);

        long failedCount = logRepository.countByIpAddressAndStatusCodeAndTimestampAfter(
                ip, 401, fiveMinAgo);

        if (failedCount >= 5 &&
                !alertRepository.existsByAlertTypeAndSourceIpAndResolvedFalse(
                        AlertType.BRUTE_FORCE, ip)) {

            SecurityAlert alert = new SecurityAlert(
                    AlertType.BRUTE_FORCE,
                    Severity.CRITICAL,
                    "Brute force attack detected: " + failedCount +
                            " failed login attempts from IP " + ip + " in last 5 minutes",
                    ip,
                    log.getUsername()
            );
            alertRepository.save(alert);
        }
    }

    /**
     * Rule 2: Privilege Escalation Detection
     * IF 5+ requests with status 403 from same user in last 5 minutes
     * AND no unresolved PRIVILEGE_ESCALATION alert exists for this user
     * THEN create HIGH alert
     */
    private void checkPrivilegeEscalation(ApiLog log) {
        if (log.getStatusCode() != 403) return;
        if ("ANONYMOUS".equals(log.getUsername())) return;

        String username = log.getUsername();
        LocalDateTime fiveMinAgo = LocalDateTime.now().minusMinutes(5);

        long forbiddenCount = logRepository.countByUsernameAndStatusCodeAndTimestampAfter(
                username, 403, fiveMinAgo);

        if (forbiddenCount >= 5 &&
                !alertRepository.existsByAlertTypeAndTargetUsernameAndResolvedFalse(
                        AlertType.PRIVILEGE_ESCALATION, username)) {

            SecurityAlert alert = new SecurityAlert(
                    AlertType.PRIVILEGE_ESCALATION,
                    Severity.HIGH,
                    "Possible privilege escalation: user '" + username +
                            "' made " + forbiddenCount +
                            " forbidden requests in last 5 minutes",
                    log.getIpAddress(),
                    username
            );
            alertRepository.save(alert);
        }
    }

    /**
     * Rule 3: Rapid Access / DDoS Detection
     * IF 25+ requests from same IP in last 1 minute
     * AND no unresolved RAPID_ACCESS alert exists for this IP
     * THEN create MEDIUM alert
     */
    private void checkRapidAccess(ApiLog log) {
        String ip = log.getIpAddress();
        LocalDateTime oneMinAgo = LocalDateTime.now().minusMinutes(1);

        long requestCount = logRepository.countByIpAddressAndTimestampAfter(ip, oneMinAgo);

        if (requestCount >= 25 &&
                !alertRepository.existsByAlertTypeAndSourceIpAndResolvedFalse(
                        AlertType.RAPID_ACCESS, ip)) {

            SecurityAlert alert = new SecurityAlert(
                    AlertType.RAPID_ACCESS,
                    Severity.MEDIUM,
                    "Rapid access detected: " + requestCount +
                            " requests from IP " + ip + " in last 1 minute",
                    ip,
                    log.getUsername()
            );
            alertRepository.save(alert);
        }
    }

    /**
     * Rule 4: Blocked User Access (called externally by UserService)
     * When a blocked user attempts to login, this creates a HIGH alert.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void raiseBlockedUserAlert(String username, String details) {
        if (!alertRepository.existsByAlertTypeAndTargetUsernameAndResolvedFalse(
                AlertType.BLOCKED_USER_ACCESS, username)) {

            SecurityAlert alert = new SecurityAlert(
                    AlertType.BLOCKED_USER_ACCESS,
                    Severity.HIGH,
                    "Blocked user '" + username + "' attempted to login. " + details,
                    null,
                    username
            );
            alertRepository.save(alert);
        }
    }
}
