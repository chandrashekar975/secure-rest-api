package com.company.secureapi.audit;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "api_logs")
public class ApiLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String endpoint;
    private String method;
    private int statusCode;
    private String ipAddress;
    private LocalDateTime timestamp;

    public ApiLog() {}

    public ApiLog(String username, String endpoint, String method, int statusCode, String ipAddress) {
        this.username = username;
        this.endpoint = endpoint;
        this.method = method;
        this.statusCode = statusCode;
        this.ipAddress = ipAddress;
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEndpoint() { return endpoint; }
    public String getMethod() { return method; }
    public int getStatusCode() { return statusCode; }
    public String getIpAddress() { return ipAddress; }
    public LocalDateTime getTimestamp() { return timestamp; }

    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
}
