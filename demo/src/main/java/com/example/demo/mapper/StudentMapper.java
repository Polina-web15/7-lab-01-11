package com.example.demo.mapper;

import java.util.stream.Collectors;

import com.example.demo.dto.StudentDto;
import com.example.demo.dto.StudentLoggedDto;
import com.example.demo.model.Permission;
import com.example.demo.model.Student;

public class StudentMapper {
    public static StudentDto studentToStudentDto (Student student) {
        return new StudentDto(student.getId(),
        student.getUsername(),
        student.getPassword(),
        student.getRole().getAuthority(),
        student.getRole().getPermissions().stream().map(Permission::getAuthority).collect(Collectors.toSet()));
    }

    public static StudentLoggedDto studentToStudentLoggedDto (Student student) {
        return new StudentLoggedDto(student.getUsername(),
        student.getRole().getAuthority(),
        student.getRole().getPermissions().stream().map(Permission::getAuthority).collect(Collectors.toSet()));
    }
}
