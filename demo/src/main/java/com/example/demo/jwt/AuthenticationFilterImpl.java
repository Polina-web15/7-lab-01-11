package com.example.demo.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthenticationFilterImpl extends UsernamePasswordAuthenticationFilter{
    private final AuthenticationManager authenticationManager;

    //@Override
    public Authentication attempAuthentication(HttpServletRequest request, HttpServletResponse response)
    throws AuthenticationException{
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
            request.getParameter("username"), ((ServletRequest) response).getParameter("password")));
            
    }
}
