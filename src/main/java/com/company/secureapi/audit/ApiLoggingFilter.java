package com.company.secureapi.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ApiLoggingFilter extends OncePerRequestFilter {

    private final ApiLogRepository apiLogRepository;
    private final AuditRuleEngine auditRuleEngine;

    public ApiLoggingFilter(ApiLogRepository apiLogRepository, AuditRuleEngine auditRuleEngine) {
        this.apiLogRepository = apiLogRepository;
        this.auditRuleEngine = auditRuleEngine;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // First proceed with request execution
        try {
            filterChain.doFilter(request, response);
        } finally {
            // After request is processed, log and evaluate rules
            logAndEvaluate(request, response);
        }
    }

    private void logAndEvaluate(HttpServletRequest request, HttpServletResponse response) {
        String username = "ANONYMOUS";
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            username = auth.getName();
        }

        String endpoint = request.getRequestURI();
        String method = request.getMethod();
        int status = response.getStatus();

        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        // Save the log entry
        ApiLog log = new ApiLog(username, endpoint, method, status, ipAddress);
        apiLogRepository.save(log);

        // Evaluate security rules against this log entry
        if (auditRuleEngine != null) {
            auditRuleEngine.evaluate(log);
        }
    }
}
