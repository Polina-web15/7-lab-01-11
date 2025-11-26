package com.example.demo.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.example.demo.model.TimeEntry;
import com.example.demo.repository.TimeEntryRepository;

//import ch.qos.logback.core.util.Duration;
import java.time.Duration;
import jakarta.transaction.Transactional;

@Service
@Transactional
public class TimeEntryService {
    private final TimeEntryRepository timeEntryRepository;

    public TimeEntryService(TimeEntryRepository timeEntryRepository) {
        this.timeEntryRepository = timeEntryRepository;
    }
    // Получение всех записей
    public List<TimeEntry> getAll() {
        return timeEntryRepository.findAll();
    }
    // Сохранение записи
    public TimeEntry save(TimeEntry timeEntry) {
        validateTimeEntry(timeEntry);
        return timeEntryRepository.save(timeEntry);
    }

    // Получение по ID
    public TimeEntry getById(Long id) {
        return timeEntryRepository.findById(id).orElse(null);
    }
    // Удаление записи
    public void deleteById(Long id) {
        timeEntryRepository.deleteById(id);
    }

    // Расчёт продолжительности в минутах
    public long getDurationInMinutes(TimeEntry timeEntry) {
        if (timeEntry.getStart() == null || timeEntry.getEnd() == null) {
            throw new IllegalArgumentException("Start and end times must be set to calculate duration.");
        }
        return Duration.between(timeEntry.getStart(), timeEntry.getEnd()).toMinutes();
    }

    // Проверка корректности данных
    private void validateTimeEntry(TimeEntry timeEntry) {
        if (timeEntry.getStart() == null || timeEntry.getEnd() == null) {
            throw new IllegalArgumentException("Start and end times are required.");
        }
        if (!timeEntry.getEnd().isAfter(timeEntry.getStart())) {
            throw new IllegalArgumentException("End time must be after start time.");
        }
    }
    public TimeEntry update(Long id, TimeEntry timeEntry){
         return timeEntryRepository.findById(id).map(existingTimeEntry -> {
            existingTimeEntry.setStudent(timeEntry.getStudent());
            existingTimeEntry.setDescription(timeEntry.getDescription());
            return timeEntryRepository.save(existingTimeEntry);
        }).orElse(null);
    }
}
