package com.example.demo.controller;

//import java.time.LocalDateTime;
//import java.util.ArrayList;
//import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.RestController;


import com.example.demo.model.Student;
import com.example.demo.service.StudentService;

import jakarta.validation.Valid;

import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PutMapping;




@RestController
public class StudentController {
    private final StudentService studentService;
   // private List<Student> students = new ArrayList<>(Arrays.asList());
    //recentEntries = times для однго студента,
    public StudentController(StudentService studentService){
        this.studentService = studentService;
    }
    @GetMapping("/students")
    public List<Student> getStudents() {
        return studentService.getAll();
    }
    
    // @GetMapping("/students/{id}")
    // public ResponseEntity<Student> getStudent(@PathVariable long id) {
    //     for (Student student: students){
    //         if (student.getId().equals(id)){
    //             return ResponseEntity.ok(student);
    //         }
    //     }
    //     return ResponseEntity.notFound().build();
    // }
    @PutMapping("students/{id}")
    public ResponseEntity<Student> edit(@PathVariable Long id, @RequestBody Student student) {
        Student updated = studentService.update(id, student);
        if(updated != null){
            return ResponseEntity.ok(updated);
        }
        return ResponseEntity.notFound().build();
    }
    @GetMapping("/students/{id}")
    public ResponseEntity<Student> getStudents(@PathVariable Long id) {//true
        Student p = studentService.getById(id);
        if(p != null){
            return ResponseEntity.ok(p);
        }
        return ResponseEntity.notFound().build();
    }
    @DeleteMapping("/students/{id}")
     public ResponseEntity<Void> delete(@PathVariable Long id){
        if(studentService.deleteById(id)){
            return ResponseEntity.noContent().build();
         }
          return ResponseEntity.ok().build();
    }

    @PostMapping("/students")
    public ResponseEntity<Student> addStudent(@RequestBody @Valid Student student) {
        Student newStudent = studentService.create(student);
        return ResponseEntity.status(HttpStatus.CREATED).body(newStudent);
    }
    @GetMapping("/filter")
    public ResponseEntity<Object> getByFilter(
    @RequestParam(required = false) String name,
    @RequestParam(required = false) String groupName,
    @PageableDefault(page=0, size=10, sort="name")
    Pageable pageable) {
        return ResponseEntity.ok(studentService.getByFilter(name, groupName, pageable));
    }
}
