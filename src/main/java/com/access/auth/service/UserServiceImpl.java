package com.access.auth.service;

import java.util.Calendar;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.access.auth.entities.User;
import com.access.auth.entities.VerificationToken;
import com.access.auth.models.UserModel;
import com.access.auth.repositories.UserRepo;
import com.access.auth.repositories.VerificationTokenRepo;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserRepo userRepo;

	@Autowired
	private VerificationTokenRepo verficationTokenRepo;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public User registerUser(UserModel userModel) {
		User user = new User();

		user.setUserName(userModel.getUserName());
		user.setEmail(userModel.getEmail());
		user.setPassword(passwordEncoder.encode(userModel.getPassword()));
		user.setRole("USER");

		userRepo.save(user);
		
		return user;
	}

	@Override
	public void saveVerificationTokenForUser(String token, User user) {
		VerificationToken verificationToken = new VerificationToken(user, token);

		verficationTokenRepo.save(verificationToken);
	}

	@Override
	public boolean validateVerificationToken(String token) {
		VerificationToken verificationToken = verficationTokenRepo.findByToken(token);

		if (verificationToken == null)
			return false;

		User user = verificationToken.getUser();
		Calendar cal = Calendar.getInstance();

		if (verificationToken.getExpirationTime().getTime() - cal.getTime().getTime() <= 0) {
			verficationTokenRepo.delete(verificationToken);
			return false;
		}
		
		user.setEnabled(true);
		userRepo.save(user);

		return true;
	}

	@Override
	public VerificationToken generateNewVerificationToken(String oldToken) {
		
		VerificationToken verificationToken = verficationTokenRepo.findByToken(oldToken);
		
		verificationToken.setToken(UUID.randomUUID().toString());
		verficationTokenRepo.save(verificationToken);
		
		return verificationToken;
	}
}
