package com.example.mediumreactivewebflux5security_db.config;

import com.example.mediumreactivewebflux5security_db.model.Role;
import com.example.mediumreactivewebflux5security_db.model.User;
import com.example.mediumreactivewebflux5security_db.repository.ReactiveUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ApplicationConfiguration {

    private final ReactiveUserRepository reactiveUserRepository;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveUserDetailsService reactiveUserDetailsService() {
        return username -> reactiveUserRepository.findByUsername(username)
                .map(user -> new org.springframework.security.core.userdetails.User(
                                user.getUsername(),
                                user.getPassword(),
                                user.getAuthorities()
                        )
                );
    }

    @Bean
    public CommandLineRunner commandLineRunner() {
        return args -> {
            User user = new User();
            user.setUserId("1");
            user.setUsername("user");
            user.setPassword(passwordEncoder().encode("user"));
            user.setEnabled(true);
            user.setRoles(List.of(Role.ROLE_USER));

            User admin = new User();
            admin.setUserId("2");
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder().encode("admin"));
            admin.setEnabled(true);
            admin.setRoles(List.of(Role.ROLE_USER, Role.ROLE_ADMIN));

            reactiveUserRepository.saveAll(List.of(user, admin)).blockLast();
        };
    }

}
