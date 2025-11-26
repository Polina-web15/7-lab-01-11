package com.example.demo.dto;
import java.io.Serializable;
import java.util.Set;

public record StudentDto(Long id, 
String name, 
String password, 
String role, 
Set<String> permissions) implements Serializable { 
}
