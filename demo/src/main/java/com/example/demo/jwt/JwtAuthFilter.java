package com.example.demo.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    private final StudentDetailsServiceImpl studentDetailsService;

    @Value("${jwt.access.cookie-name}")
    private String accessCookieName;

    

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String token = "";
        if (cookies != null) {
            for (Cookie cookie: cookies) {
                if(accessCookieName.equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
            }
        }
        }       

        if (token == "" || !jwtTokenProvider.isValid(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtTokenProvider.getUsername(token);
        if (username == null) {
            filterChain.doFilter(request, response);
            return;
        }

        UserDetails studentDetails = studentDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(studentDetails, null, studentDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
