package com.ye.backend.service;

import com.ye.backend.models.Note;

import java.util.List;

public interface INoteService {

    Note createNoteForUser(String username, String content);

    Note updateNoteForUser(Long noteId, String content, String username);

    void deleteNoteForUser(Long noteId, String username);

    List<Note> getNotesForUser(String username);
}
