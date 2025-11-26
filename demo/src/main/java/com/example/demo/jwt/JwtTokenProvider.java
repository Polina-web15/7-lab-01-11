package com.example.demo.jwt;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.example.demo.enums.TokenType;
import com.example.demo.model.Token;
import com.example.demo.repository.TokenRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String key;

    private final TokenRepository tokenRepository;

    private boolean isDisabled(String value) {
        Token token = tokenRepository.findByValue(value).orElse(null);

        if (token == null) return true;

        return token.isDisabled();
    }

    private Date toDate(LocalDateTime time) {
        return Date.from(time.toInstant(ZoneOffset.UTC));
    }

    private LocalDateTime toLocalDateTime (Date time) {
        return time.toInstant().atOffset(ZoneOffset.UTC).toLocalDateTime();
    }

    private Claims extractAllClaims(String value) {///kkk
        return Jwts.parserBuilder().setSigningKey(decodeSecretKey(key)).build().parseClaimsJwt(value).getBody();
    }

    private Key decodeSecretKey(String key) {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    public String getUsername (String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public LocalDateTime getExpiration(String token) {
        return toLocalDateTime(extractClaim(token, Claims::getExpiration));
    }

    public boolean isValid (String token) {
        if (token == null) return false;
        try {
            Jwts.parserBuilder().setSigningKey(decodeSecretKey(key)).build().parseClaimsJwt(token);
            return !isDisabled(token);
        }
        catch (JwtException e) {
            return false;
        }
    }

    public Token generateAccessToken (Map <String, Object> extra, long duration, TemporalUnit durationType, UserDetails student) {
        String username = student.getUsername();

        LocalDateTime now = LocalDateTime.now();

        LocalDateTime expirationDate = now.plus(duration, durationType);

        String value = Jwts.builder().setClaims(extra).setSubject(username).setIssuedAt(toDate(now)).setExpiration(toDate(expirationDate))
        .signWith(decodeSecretKey(key), SignatureAlgorithm.HS256).compact();

        return new Token(TokenType.ACCESS, value, expirationDate, false, null);
    }

    public Token generateRefreshToken (long duration, TemporalUnit durationType, UserDetails student) {
        String username = student.getUsername();

        LocalDateTime now = LocalDateTime.now();

        LocalDateTime expirationDate = now.plus(duration, durationType);

        String value = Jwts.builder().setSubject(username).setIssuedAt(toDate(now)).setExpiration(toDate(expirationDate))
        .signWith(decodeSecretKey(key), SignatureAlgorithm.HS256).compact();

        return new Token(TokenType.REFRESH, value, expirationDate, false, null);
    }
}
