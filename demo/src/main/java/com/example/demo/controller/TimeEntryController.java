package com.example.demo.controller;

//import static org.mockito.Mockito.times;

//import java.util.ArrayList;
//import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.RestController;

//import com.example.demo.model.TaskType;
//import com.example.demo.model.RiskLevel;
import com.example.demo.model.TimeEntry;
import com.example.demo.service.TimeEntryService;

//import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class TimeEntryController {

    private final TimeEntryService timeEntryService;

    // Используем конструктор для внедрения зависимости (рекомендуется)
    public TimeEntryController(TimeEntryService timeEntryService) {
        this.timeEntryService = timeEntryService;
    }
    @GetMapping("/times")
    public List<TimeEntry> getTimes() {
        return timeEntryService.getAll();
    }

    @PutMapping("/times/{id}")
    public ResponseEntity<TimeEntry> edit(@PathVariable long id, @RequestBody TimeEntry timeEntry) {
        TimeEntry updated = timeEntryService.update(id, timeEntry);
        if(updated != null){
            return ResponseEntity.ok(updated);
        }
        return ResponseEntity.notFound().build();
    }

    // Получить запись по ID
    @GetMapping("/times/{id}")
    public ResponseEntity<TimeEntry> getTimeEntryById(@PathVariable Long id) {
        TimeEntry entry = timeEntryService.getById(id);
        if(entry != null){
            return ResponseEntity.ok(entry);
        }
        return ResponseEntity.notFound().build();
    }

    // Создать новую запись
    @PostMapping("/times")
    public ResponseEntity<TimeEntry> createTimeEntry(@RequestBody TimeEntry timeEntry) {
        TimeEntry savedEntry = timeEntryService.save(timeEntry);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedEntry);
    }

    // Удалить запись
    @DeleteMapping("/times/{id}")
    public ResponseEntity<Void> deleteTimeEntry(@PathVariable Long id) {
        timeEntryService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    // Дополнительно: получить длительность в минутах
}
    // @PostMapping("/times")
    // public ResponseEntity<TimeEntry> addTime(@RequestBody @Valid TimeEntry time) {
    //     time.setId((long)times.size() + 1);
    //     times.add(time);
    //     return ResponseEntity.status(HttpStatus.CREATED).body(time);
    // }    
 //LocalDateTime start;
    //LocalDateTime end;