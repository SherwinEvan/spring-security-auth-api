package com.access.auth.service;

import org.springframework.stereotype.Service;

import com.access.auth.entities.User;
import com.access.auth.models.UserModel;


@Service
public interface UserService {
	
	public User registerUser(UserModel userModel);

	public void saveVerificationTokenForUser(String token, User user);

	public boolean validateVerificationToken(String token);
}
