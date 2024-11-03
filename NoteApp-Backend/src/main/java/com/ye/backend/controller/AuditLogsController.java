package com.ye.backend.controller;

import com.ye.backend.models.AuditLogs;
import com.ye.backend.service.impl.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
@CrossOrigin(origins = "http://localhost:3000" , maxAge = 3600, allowCredentials = "true")
public class AuditLogsController {

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLogs> getAuditLogs(){
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{noteid}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLogs> getNoteAuditLogs(@PathVariable Long noteid ){
        return auditLogService.getAuditLogsForNoteId(noteid);
    }
}
