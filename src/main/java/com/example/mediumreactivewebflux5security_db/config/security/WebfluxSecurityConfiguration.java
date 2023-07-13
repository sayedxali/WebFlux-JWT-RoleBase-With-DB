package com.example.mediumreactivewebflux5security_db.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class WebfluxSecurityConfiguration {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity.csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint((serverWebExchange, exception) ->
                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(UNAUTHORIZED))
                ).accessDeniedHandler((serverWebExchange, deniedException) ->
                        Mono.fromRunnable(() -> serverWebExchange.getResponse().setStatusCode(FORBIDDEN))
                ).and()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange(authorizeExchangeSpec -> {
                    authorizeExchangeSpec
                            .pathMatchers("/login").permitAll()
                            .pathMatchers(HttpMethod.OPTIONS).permitAll()
                            .anyExchange().authenticated();
                });
        return httpSecurity.build();
    }

}
