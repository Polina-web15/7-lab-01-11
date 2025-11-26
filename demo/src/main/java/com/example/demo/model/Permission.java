package com.example.demo.model;

import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
//import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
public class Permission implements GrantedAuthority{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    String resource;
    @Column(nullable = false)
    String operation;
    @ManyToMany(mappedBy = "permissions")
    private  Set<Role> roles;

    @Override
    public String getAuthority(){
        return String.format("%s:%s", resource.toUpperCase(), operation.toUpperCase());
    }
}
