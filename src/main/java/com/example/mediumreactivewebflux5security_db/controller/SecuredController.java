package com.example.mediumreactivewebflux5security_db.controller;

import com.example.mediumreactivewebflux5security_db.dto.Message;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/secured")
public class SecuredController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public Mono<ResponseEntity<Message>> user() {
        return Mono.just(ResponseEntity.ok(new Message("User resource")));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<Message>> admin() {
        return Mono.just(ResponseEntity.ok(new Message("Admin resource")));
    }

    @GetMapping("/resource/user-or-admin")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public Mono<ResponseEntity<Message>> userOrAdmin() {
        return Mono.just(ResponseEntity.ok(new Message("User or Admin resource")));
    }

}
