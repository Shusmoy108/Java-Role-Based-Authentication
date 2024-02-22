package com.foyob.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.foyob.security.model.User;
import com.foyob.security.service.UserService;

@Component
public class JwtToUserConverter implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

	@Autowired
	UserService userService;
	
	@Override
	public UsernamePasswordAuthenticationToken convert(Jwt jwt) {
		User user= (User) userService.loadUserByUsername(jwt.getSubject());
		user.setPassword("");
		return new UsernamePasswordAuthenticationToken(user,jwt, user.getAuthorities());
	}
	

}

