package com.example.demo.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.LoginRequestDto;
import com.example.demo.dto.LoginResponseDto;
import com.example.demo.dto.StudentLoggedDto;
import com.example.demo.service.AuthenticationService;

import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
           @CookieValue(name="access-token", required=false) String access, 
           @CookieValue(name="refresh-token", required=false) String refresh,
           @RequestBody LoginRequestDto request){        
        return authenticationService.login(request, access, refresh);
    }
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(
           @CookieValue(name="refresh-token", required=true) String refresh){ 
        return authenticationService.refresh(refresh);
    }

    @PostMapping("/logout")
    public ResponseEntity<LoginResponseDto> logout(
           @CookieValue(name="access-token", required=false) String access){ 
        return authenticationService.logout(access);
    }

    @GetMapping("/info")
    public ResponseEntity<StudentLoggedDto> info(
           @CookieValue(name="access-token", required=false) String refresh){ 
        return ResponseEntity.ok(authenticationService.info());
    }
}
