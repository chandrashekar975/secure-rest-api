package com.company.secureapi.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;

public interface ApiLogRepository extends JpaRepository<ApiLog, Long> {

    // Existing queries
    List<ApiLog> findAllByOrderByTimestampDesc();
    List<ApiLog> findByStatusCodeGreaterThanEqualOrderByTimestampDesc(int statusCode);

    // Rule engine queries
    long countByIpAddressAndStatusCodeAndTimestampAfter(String ipAddress, int statusCode, LocalDateTime after);
    long countByUsernameAndStatusCodeAndTimestampAfter(String username, int statusCode, LocalDateTime after);
    long countByIpAddressAndTimestampAfter(String ipAddress, LocalDateTime after);

    // Stats queries
    long countByStatusCode(int statusCode);
    long countByTimestampAfter(LocalDateTime after);
}
