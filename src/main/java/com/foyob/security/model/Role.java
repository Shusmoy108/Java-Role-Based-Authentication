package com.foyob.security.model;


import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Role {
	USER("USER"),
	ADMIN("ADMIN"),
	MANAGER("MANAGER")
	;

	@Getter
	private final String role;
	
	
	public List<SimpleGrantedAuthority> getAuthorities() {
		List<SimpleGrantedAuthority> authorities= new ArrayList<SimpleGrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
	    return authorities;
	    
	}
}
