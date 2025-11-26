package com.example.demo.service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.example.demo.dto.LoginRequestDto;
import com.example.demo.dto.LoginResponseDto;
import com.example.demo.dto.StudentLoggedDto;
import com.example.demo.jwt.JwtTokenProvider;
import com.example.demo.mapper.StudentMapper;
import com.example.demo.model.Student;
import com.example.demo.model.Token;
import com.example.demo.repository.TokenRepository;
//import com.example.demo.repository.StudentRepository;
import com.example.demo.util.CookieUtil;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AuthenticationService {
    //private final StudentRepository studentRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieUtil cookieUtil;
    private final AuthenticationManager authenticationManager;
    private final StudentService studentService;

    @Value("${jwt.access.duration.minute}")
    private long accessDurationMin;
    @Value("${jwt.access.duration.second}")
    private long accessDurationSec;
    @Value("${jwt.refresh.duration.days}")
    private long refreshDurationDate;
    @Value("${jwt.refresh.duration.second}")
    private long refreshDurationSec;

    private void addAccessTokenCookie(HttpHeaders headers, Token token) {
        headers.add(HttpHeaders.SET_COOKIE, cookieUtil.createAccessCookie(token.getValue(), accessDurationSec).toString());
    }

    private void addRefreshTokenCookie(HttpHeaders headers, Token token) {
        headers.add(HttpHeaders.SET_COOKIE, cookieUtil.createRefreshCookie(token.getValue(), refreshDurationSec).toString());
    }

    private void revokeAllTokens(Student student) {
        Set <Token> tokens = student.getTokens();
        
        tokens.forEach(token -> {if(token.getExpiringDate().isBefore(LocalDateTime.now())) tokenRepository.delete(token);
        else if(!token.isDisabled()) {
            token.setDisabled(true);
            tokenRepository.save(token);
        }});
    }

    public ResponseEntity<LoginResponseDto> login(LoginRequestDto request, String access, String refresh) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
            request.username(), request.password()));
        Student student = studentService.getStudent(request.username());

        boolean accessValid = jwtTokenProvider.isValid(access);
        boolean refreshValid = jwtTokenProvider.isValid(refresh);

        HttpHeaders headers = new HttpHeaders();

        revokeAllTokens(student);//

        if (!accessValid) {
            Token newAccess = jwtTokenProvider.generateAccessToken(Map.of("role", student.getRole().getAuthority()),
            accessDurationMin, ChronoUnit.MINUTES, student);

            newAccess.setStudent(student);
            addAccessTokenCookie(headers, newAccess);
            tokenRepository.save(newAccess);
        }

        if (!refreshValid || accessValid) {
            Token newRefresh = jwtTokenProvider.generateRefreshToken(refreshDurationDate, ChronoUnit.MINUTES, student);

            newRefresh.setStudent(student);
            addRefreshTokenCookie(headers, newRefresh);
            tokenRepository.save(newRefresh);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return ResponseEntity.ok().headers(headers).body(new LoginResponseDto(true, student.getRole().getName()));
    }
    public ResponseEntity <LoginResponseDto> refresh(String refreshToken){
        if (!jwtTokenProvider.isValid(refreshToken)){
            throw new RuntimeException("token is invalid");
        }

        Student student = studentService.getStudent(jwtTokenProvider.getUsername(refreshToken));

        Token newAccess = jwtTokenProvider.generateAccessToken(Map.of("role", student.getRole().getAuthority()),
           accessDurationMin,  ChronoUnit.MINUTES, student);

        HttpHeaders headers = new HttpHeaders();
        addAccessTokenCookie(headers, newAccess);

        return ResponseEntity.ok().headers(headers).body(new LoginResponseDto(true, student.getRole().getName()));
    }
    public ResponseEntity <LoginResponseDto> logout(String accessToken){
        SecurityContextHolder.clearContext();
        Student student = studentService.getStudent(jwtTokenProvider.getUsername(accessToken));
        revokeAllTokens(student);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteAccessCookie().toString());
        headers.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteRefreshCookie().toString());
        
        return ResponseEntity.ok().headers(headers).body(new LoginResponseDto(false, null));
    }
    public StudentLoggedDto info() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
         if (authentication instanceof AnonymousAuthenticationToken){
            throw new RuntimeException("No user");
        }

        Student student = studentService.getStudent(authentication.getName());

        return StudentMapper.studentToStudentLoggedDto(student);
    }

}
