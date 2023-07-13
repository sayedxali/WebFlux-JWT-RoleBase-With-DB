package com.example.mediumreactivewebflux5security_db.controller;

import com.example.mediumreactivewebflux5security_db.config.jwt.JWTUtil;
import com.example.mediumreactivewebflux5security_db.dto.AuthRequest;
import com.example.mediumreactivewebflux5security_db.dto.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {

    private final JWTUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final ReactiveUserDetailsService userService;

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest) {
        return userService.findByUsername(authRequest.getUsername())
                .filter(userDetails ->
                        passwordEncoder.matches(
                                authRequest.getPassword(),
                                userDetails.getPassword()
                        )
                ).map(userDetails -> ResponseEntity.ok(new AuthResponse(jwtUtil.generateToken(userDetails))))
                .switchIfEmpty(Mono.just(ResponseEntity.status(UNAUTHORIZED).build()));
    }

}
