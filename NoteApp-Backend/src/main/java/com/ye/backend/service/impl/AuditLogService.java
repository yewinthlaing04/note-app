package com.ye.backend.service.impl;

import com.ye.backend.models.AuditLogs;
import com.ye.backend.models.Note;
import com.ye.backend.repository.AuditLogRepository;
import com.ye.backend.repository.NoteRepository;
import com.ye.backend.service.IAuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogService implements IAuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;


    @Override
    public void logNoteCreation(String username, Note note) {
        AuditLogs auditLogs = new AuditLogs();
        auditLogs.setAction("CREATE");
        auditLogs.setUsername(username);
        auditLogs.setNoteId(note.getId());
        auditLogs.setNoteContent(note.getContent());
        auditLogs.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(auditLogs);
    }

    @Override
    public void logNoteUpdate(String username, Note note) {
        AuditLogs auditLog = new AuditLogs();
        auditLog.setAction("UPDATE");
        auditLog.setUsername(username);
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(auditLog);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLogs log = new AuditLogs();
        log.setAction("DELETE");
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(log);
    }

    @Override
    public List<AuditLogs> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLogs> getAuditLogsForNoteId(Long id) {
        return auditLogRepository.findByNoteId(id);
    }
}
