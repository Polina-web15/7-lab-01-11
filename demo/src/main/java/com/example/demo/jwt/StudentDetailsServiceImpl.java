package com.example.demo.jwt;


import com.example.demo.repository.StudentRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class StudentDetailsServiceImpl implements UserDetailsService {

    private final StudentRepository studentRepository;

    StudentDetailsServiceImpl(StudentRepository studentRepository) {
        this.studentRepository = studentRepository;
    }
   @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return studentRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}
