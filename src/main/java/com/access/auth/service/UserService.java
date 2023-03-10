package com.access.auth.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.access.auth.entities.User;
import com.access.auth.entities.VerificationToken;
import com.access.auth.models.UserModel;

import jakarta.servlet.http.HttpServletRequest;


@Service
public interface UserService {
	
	public User registerUser(UserModel userModel);

	public void saveVerificationTokenForUser(String token, User user);

	public boolean validateVerificationToken(String token);

	public VerificationToken generateNewVerificationToken(String oldToken);

	public User findUserByEmail(String email);

	public void createPasswordResetTokenForUser(User user, String token);

	public boolean validatePasswordResetToken(String token);

	public Optional<User> getUserByPasswordResetToken(String token);

	public void changePassword(User user, String newPassword);

	public boolean checkIfValidOldPassword(User user, String oldPassword);
}
