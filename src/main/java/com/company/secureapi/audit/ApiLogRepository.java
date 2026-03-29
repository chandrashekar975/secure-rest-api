package com.company.secureapi.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ApiLogRepository extends JpaRepository<ApiLog, Long> {
    List<ApiLog> findAllByOrderByTimestampDesc();
}
