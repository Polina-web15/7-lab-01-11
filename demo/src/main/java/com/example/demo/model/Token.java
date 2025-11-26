package com.example.demo.model;

import java.time.LocalDateTime;

import com.example.demo.enums.TokenType;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Data
@Entity
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private TokenType type;

    private String value;

    private LocalDateTime expiringDate;

    private boolean disabled;

    @ManyToOne
    private Student student;

    public Token(TokenType type, String value, LocalDateTime expiringDate, boolean disabled, Student student) {
        this.type = type;
        this.value = value;
        this.expiringDate = expiringDate;
        this.disabled = disabled;
        this.student = student;
    }
}
