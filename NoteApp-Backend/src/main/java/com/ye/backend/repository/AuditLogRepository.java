package com.ye.backend.repository;

import com.ye.backend.models.AuditLogs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogs , Long> {

    List<AuditLogs> findByNoteId(Long id);
}
