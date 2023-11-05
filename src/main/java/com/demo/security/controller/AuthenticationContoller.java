package com.demo.security.controller;

import com.demo.security.DTO.Login;
import com.demo.security.model.User;
import com.demo.security.repository.UserRepository;
import com.demo.security.security.TokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationContoller {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<String> register(@RequestBody User user) {
        String encode = new BCryptPasswordEncoder().encode(user.getPassword());
        user.setPassword(encode);
        userRepository.save(user);
        return ResponseEntity.ok().body("User created");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> login(@RequestBody Login user) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.email(), user.password());
        System.err.println(token);
        Authentication authenticate = authenticationManager.authenticate(token);
        System.err.println(authenticate);
        String tokenJWT = tokenService.generateToken((User) authenticate.getPrincipal());
        return ResponseEntity.ok().body(tokenJWT);
//        return ResponseEntity.ok("Tete de método");
    }
}
