package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;


import com.example.demo.model.TimeEntry;

public interface TimeEntryRepository extends
JpaRepository<TimeEntry, Long>{
        List<TimeEntry> findByStudent_NameStartingWithIgnoreCase(String studentName);
        List<TimeEntry> findAllByStudent_Name(String studentName);
}
