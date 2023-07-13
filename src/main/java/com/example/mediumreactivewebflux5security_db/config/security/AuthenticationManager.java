package com.example.mediumreactivewebflux5security_db.config.security;

import com.example.mediumreactivewebflux5security_db.config.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final JWTUtil jwtUtil;
    private final ReactiveUserDetailsService userDetailsService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = authentication.getCredentials().toString();
        log.info("token ReactiveAuthManager : {}", token);
        String username = jwtUtil.extractUsername(token);
        return userDetailsService.findByUsername(username)
                .map(userDetails -> {
                    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                    return new UsernamePasswordAuthenticationToken(
                            username,
                            token,
                            authorities
                    );
                }) // casting to Mono<Authentication> since it was returning Mono<UsernamePasswordAuthenticationToken>
                .map(authenticationToken -> (Authentication) authenticationToken)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")));
    }
}
