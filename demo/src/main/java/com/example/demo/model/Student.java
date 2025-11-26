package com.example.demo.model;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
//import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "student100")
public class Student implements UserDetails {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotBlank
    //@Size(min = 2, max = 100, message = "demo")
    @Column(name = "name", nullable = false, unique = false, length = 100)
    private String name;
    @Column(name = "group_name") // ← явно задаём имя столбца
    private String groupName;
    @NotBlank
    @Column(nullable = false, unique = true)
    String username;
    @NotBlank
    @Column(nullable = true)
    String password;
    
    @ManyToOne
    private Role role;

    @OneToMany(mappedBy = "student")
    private Set <Token> tokens;
    
    @OneToMany(mappedBy = "student", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<TimeEntry> recentEntries;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        Set<String> authorities = new  HashSet<>();
        this.role.getPermissions().forEach(p -> authorities.add(p.getAuthority()));
        authorities.add(role.getAuthority());
        return authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());   
    }
    //@ElementCollection
    
}
