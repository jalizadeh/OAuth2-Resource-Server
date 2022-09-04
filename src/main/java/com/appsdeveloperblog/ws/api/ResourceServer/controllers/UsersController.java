package com.appsdeveloperblog.ws.api.ResourceServer.controllers;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.appsdeveloperblog.ws.api.ResourceServer.response.UserRest;

@RestController
@RequestMapping("/users")
public class UsersController {
	
	@GetMapping("/status/check")
	public String status() {
		return "working...";
	}
	
	@PreAuthorize("hasAuthority('ROLE_developer') or #id == #jwt.subject")
	//@Secured("ROLE_developer")
	@DeleteMapping(path="/{id}")
	public String deleteUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
		return "Deleted user with id: " + id + " / JWT subject: " + jwt.getSubject();
	}
	
	@PostAuthorize("returnObject.id == #jwt.subject")
	@GetMapping(path = "/{id}")
	public UserRest getUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
		return new UserRest("6203892e-e66e-42fd-b8b5-ca720ed5045c", "Javad", "Alizadeh");
	}
}
