package com.access.auth.signupservice;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.access.auth.entities.UserEntity;
import com.access.auth.entities.VerificationToken;
import com.access.auth.models.UserModel;

import jakarta.servlet.http.HttpServletRequest;


@Service
public interface UserService {
	
	public UserEntity registerUser(UserModel userModel);

	public void saveVerificationTokenForUser(String token, UserEntity user);

	public boolean validateVerificationToken(String token);

	public VerificationToken generateNewVerificationToken(String oldToken);

	public UserEntity findUserByEmail(String email);

	public void createPasswordResetTokenForUser(UserEntity user, String token);

	public boolean validatePasswordResetToken(String token);

	public Optional<UserEntity> getUserByPasswordResetToken(String token);

	public void changePassword(UserEntity user, String newPassword);

	public boolean checkIfValidOldPassword(UserEntity user, String oldPassword);
	
	public String getTokenByUser(UserEntity User);
}

