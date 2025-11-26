package com.example.demo.dto;

public record ChangePasswordRequestDto(String oldPassword,
String newPassword,
String newAgain) {

}
