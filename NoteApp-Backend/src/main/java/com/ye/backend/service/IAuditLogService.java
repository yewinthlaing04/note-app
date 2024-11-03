package com.ye.backend.service;

import com.ye.backend.models.AuditLogs;
import com.ye.backend.models.Note;

import java.util.List;

public interface IAuditLogService {

    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

    List<AuditLogs> getAllAuditLogs();

    List<AuditLogs> getAuditLogsForNoteId(Long id);
}
