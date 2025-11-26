package com.example.demo.model;

import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.JoinTable;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
public class Role implements GrantedAuthority{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    String name;
    @OneToMany
    Set<Student> students;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
    name = "role_permission",
    joinColumns = @JoinColumn(name = "role_id"),
    inverseJoinColumns = { @JoinColumn(name = "permission_id") }
    )
    Set<Permission> permissions;

     @Override
    public String getAuthority(){
        return this.name.toUpperCase();
    }
}
