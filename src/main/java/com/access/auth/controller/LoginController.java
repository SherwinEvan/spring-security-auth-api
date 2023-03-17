package com.access.auth.controller;

import java.security.Principal;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.access.auth.entities.UserEntity;
import com.access.auth.loginservice.TokenService;
import com.access.auth.models.UserModel;
import com.access.auth.repositories.UserRepo;


@RestController
@RequestMapping("/login")
public class LoginController {

	private final TokenService tokenService;
	
	private final UserRepo userRepo;
	
	private final AuthenticationManager authenticationManager;
	
	public LoginController(TokenService tokenService, AuthenticationManager authenticationManager, UserRepo userRepo) {
		this.tokenService = tokenService;
		this.authenticationManager = authenticationManager;
		this.userRepo = userRepo;
	}

	@PostMapping("/token")
	public String token(@RequestBody UserModel loginUser) {
		
		UserEntity userEntity = userRepo.findByUserName(loginUser.getUserName());
		if(userEntity.getUserName() != null) {
			Authentication authentication = authenticationManager
												.authenticate(new UsernamePasswordAuthenticationToken(
														userEntity.getUserName(), userEntity.getPassword()
														)
												);
			return tokenService.generateToken(authentication);
		}
		return "Broken";
	}
	
	@GetMapping("/")
	public String home(Principal principal) {
		return "Hello " + principal.getName();
	}
}
