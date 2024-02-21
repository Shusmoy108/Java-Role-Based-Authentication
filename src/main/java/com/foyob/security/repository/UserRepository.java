package com.foyob.security.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.foyob.security.model.User;



public interface UserRepository extends MongoRepository<User, String>{
	Optional<User> findByUsername(String username);
	boolean existsByUsername(String username);
}
