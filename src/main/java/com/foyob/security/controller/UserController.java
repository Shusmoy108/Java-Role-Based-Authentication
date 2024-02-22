package com.foyob.security.controller;


import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.foyob.security.dto.UserDTO;
import com.foyob.security.model.User;
import com.foyob.security.repository.UserRepository;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    UserRepository userRepository;
    
    
    @GetMapping("/")
    public ResponseEntity<List<User>> getMethod() {
        return ResponseEntity.ok(userRepository.findAll());
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("#user.id == #id")
    public ResponseEntity<UserDTO> user(@AuthenticationPrincipal User user, @PathVariable String id) {
        return ResponseEntity.ok(UserDTO.from(userRepository.findById(id).orElseThrow()));
    }
}