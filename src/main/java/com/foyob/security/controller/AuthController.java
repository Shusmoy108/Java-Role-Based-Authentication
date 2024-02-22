package com.foyob.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import  org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.foyob.security.config.TokenGenerator;
import com.foyob.security.dto.LoginDTO;
import com.foyob.security.dto.SignupDTO;
import com.foyob.security.dto.TokenDTO;
import com.foyob.security.model.Role;
import com.foyob.security.model.User;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    UserDetailsManager userDetailsManager;
    @Autowired
    TokenGenerator tokenGenerator;
    @Autowired
    DaoAuthenticationProvider daoAuthenticationProvider;
    @Autowired
    @Qualifier("jwtRefreshTokenAuthProvider")
    JwtAuthenticationProvider refreshTokenAuthProvider;

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody SignupDTO signupDTO) {
    	log.info("Registering User with email {}", signupDTO.getUsername());
    	if(userDetailsManager.loadUserByUsername(signupDTO.getUsername()) != null) {
    		log.info("Registering User with email 5 {}", signupDTO.getUsername());
    		return ResponseEntity.status(HttpStatus.CONFLICT).body("User is already exist with following email "+signupDTO.getUsername());
    	}
        User user = new User(signupDTO.getUsername(), signupDTO.getPassword(), Role.ADMIN);
        userDetailsManager.createUser(user);

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(user, signupDTO.getPassword(), user.getAuthorities());

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO) {
    	log.info("Login User with email {}", loginDTO.getUsername());
        Authentication authentication = daoAuthenticationProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDTO.getUsername(), loginDTO.getPassword()));

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/token")
    public ResponseEntity<TokenDTO> token(@RequestBody TokenDTO tokenDTO) {
    	log.info("Generating new tokens from {}", tokenDTO.getRefreshToken());
        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(tokenDTO.getRefreshToken()));
        Jwt jwt = (Jwt) authentication.getCredentials();
        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }
}
