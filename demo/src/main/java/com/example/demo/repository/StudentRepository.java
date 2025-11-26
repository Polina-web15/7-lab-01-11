package com.example.demo.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import com.example.demo.model.Student;

@Repository
public interface StudentRepository extends 
        JpaRepository<Student, Long>,
        JpaSpecificationExecutor<Student>{
        List<Student> findByNameStartingWithIgnoreCase(String name);
        List<Student> findAllByName(String name);
        Optional<Student> findByUsername(String name);
}
