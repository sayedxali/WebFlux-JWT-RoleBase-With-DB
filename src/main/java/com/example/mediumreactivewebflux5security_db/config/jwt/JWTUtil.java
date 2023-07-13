package com.example.mediumreactivewebflux5security_db.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * <span style='color:white'>Step 3: Provides utility methods for working with JSON Web Tokens (JWTs).</span>
 */
@Component
public class JWTUtil {

    @Value("${jwt.secret.key}")
    private String secret;
    @Value("${jwt.secret.expirationTime}")
    private String expirationTime;
    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Extracts all claims from a JWT.
     *
     * @param token the JWT to extract claims from
     * @return a Claims object containing all claims from the JWT
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Extracts the username from a JWT.
     *
     * @param token the JWT to extract the username from
     * @return the username extracted from the JWT
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Generates a JWT for the given user details.
     *
     * @param userDetails the user details to generate the JWT for
     * @return a JWT for the given user details
     */
    public String generateToken(UserDetails userDetails) {
        return doGenerateToken(new HashMap<>(), userDetails.getUsername());
    }

    /**
     * Generates a JWT for the given claims and username.
     *
     * @param claims   the claims to include in the JWT
     * @param username the username to include in the JWT
     * @return a JWT for the given claims and username
     */
    private String doGenerateToken(Map<String, Object> claims, String username) {
        long expirationTimeLong = Long.parseLong(expirationTime); //in second
        final Date createdDate = new Date();
        final Date expirationDate = new Date(createdDate.getTime() + expirationTimeLong * 1000);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(key)
                .compact();
    }

}
