package com.example.demo.dto;

import java.util.Set;

public record StudentLoggedDto(String username,
String role,
Set <String> permissions) {

}
