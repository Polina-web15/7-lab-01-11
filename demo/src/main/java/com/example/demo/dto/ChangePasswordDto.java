package com.example.demo.dto;

import org.springframework.security.crypto.password.PasswordEncoder;

public record ChangePasswordDto(String current_password,
   String new_password,
   String new_password_again) {
  
    public boolean matches() {
        return new_password.equals(new_password_again);
    }

    
    public String encode(PasswordEncoder passwordEncoder) {
        return passwordEncoder.encode(new_password);
    }
}
