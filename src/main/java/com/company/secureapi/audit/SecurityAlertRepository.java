package com.company.secureapi.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

    // All alerts ordered by newest first
    List<SecurityAlert> findAllByOrderByCreatedAtDesc();

    // Only unresolved (active) alerts
    List<SecurityAlert> findByResolvedFalseOrderByCreatedAtDesc();

    // Count of active alerts
    long countByResolvedFalse();

    // Check if an unresolved alert already exists for a given type + IP
    boolean existsByAlertTypeAndSourceIpAndResolvedFalse(AlertType alertType, String sourceIp);

    // Check if an unresolved alert already exists for a given type + username
    boolean existsByAlertTypeAndTargetUsernameAndResolvedFalse(AlertType alertType, String targetUsername);
}
