package com.company.secureapi.audit;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_alerts")
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AlertType alertType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false, length = 500)
    private String message;

    private String sourceIp;

    private String targetUsername;

    @Column(nullable = false)
    private boolean resolved = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime resolvedAt;

    public SecurityAlert() {}

    public SecurityAlert(AlertType alertType, Severity severity, String message,
                         String sourceIp, String targetUsername) {
        this.alertType = alertType;
        this.severity = severity;
        this.message = message;
        this.sourceIp = sourceIp;
        this.targetUsername = targetUsername;
        this.createdAt = LocalDateTime.now();
    }

    // Getters
    public Long getId() { return id; }
    public AlertType getAlertType() { return alertType; }
    public Severity getSeverity() { return severity; }
    public String getMessage() { return message; }
    public String getSourceIp() { return sourceIp; }
    public String getTargetUsername() { return targetUsername; }
    public boolean isResolved() { return resolved; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getResolvedAt() { return resolvedAt; }

    // Setters for resolve
    public void setResolved(boolean resolved) { this.resolved = resolved; }
    public void setResolvedAt(LocalDateTime resolvedAt) { this.resolvedAt = resolvedAt; }
}
