package com.access.auth.controller;

import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.access.auth.entities.User;
import com.access.auth.entities.VerificationToken;
import com.access.auth.event.RegistrationCompleteEvent;
import com.access.auth.models.PasswordModel;
import com.access.auth.models.UserModel;
import com.access.auth.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class Controller {

	@Autowired
	private UserService userService;

	@Autowired
	private ApplicationEventPublisher publisher;

	@GetMapping
	public String land() {
		return "Hello!";
	}

	
	@GetMapping("/test")
	public String test() {
		return "Hello! This is a test.";
	}

	@PostMapping("/signup")
	public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request) {
		User user = userService.registerUser(userModel);

		publisher.publishEvent(new RegistrationCompleteEvent(user, applicationUrl(request)));

		return "Success";
	}

	@GetMapping("/verifyRegistration")
	public String verifyRegistration(@RequestParam("token") String token) {
		boolean validity = userService.validateVerificationToken(token);

		if (validity) {
			return "User verified successfully!";
		}

		return "Bad token request";
	}

	@GetMapping("/resendVerificationLink")
	private String resendVerificationLink(@RequestParam("token") String oldToken, HttpServletRequest request) {

		VerificationToken verificationToken = userService.generateNewVerificationToken(oldToken);
		User user = verificationToken.getUser();
		resendVerificationToken(user, applicationUrl(request), verificationToken);
		return "Verification Link Sent";
	}
	
	@PostMapping("/resetPassword")
	public String resetPassword(@RequestBody PasswordModel passwordModel, HttpServletRequest request) {
		User user = userService.findUserByEmail(passwordModel.getEmail());
		String url = "";
		if(user != null) {
			String token = UUID.randomUUID().toString();
			userService.createPasswordResetTokenForUser(user, token);
			url = passwordResetTokenMail(user, applicationUrl(request), token);
		}
		return url; 
	}
	
	@PostMapping("/savePassword")
	public String savePassword(@RequestParam String token, @RequestBody PasswordModel passwordModel) {
		boolean result = userService.validatePasswordResetToken(token);
		
		if(result == false) {
			return "Bad token";
			}
		Optional<User> user = userService.getUserByPasswordResetToken(token);
		
		if(user.isPresent()) {
			userService.changePassword(user.get(), passwordModel.getNewPassword());
			return "Password Reset Successfully!";
		}
		
		return "Bad token";
	}
	
	@PostMapping("/changePassword")
	public String changePassword(@RequestBody PasswordModel passwordModel) {
		User user = userService.findUserByEmail(passwordModel.getEmail());
		
		if(!userService.checkIfValidOldPassword(user, passwordModel.getOldPassword())) {
			return "Invalid Old Password";
		}
		
		userService.changePassword(user, passwordModel.getNewPassword());
		return "Password Change Successfully";
	}

	private String passwordResetTokenMail(User user, String applicationUrl, String token) {
		String url = applicationUrl + "/savePassword?token=" + token;

		log.info("Click the link to reset password : {}", url);
		
		return url;
	}

	private String applicationUrl(HttpServletRequest request) {
		return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
	}

	public void resendVerificationToken(User user, String applicationUrl, VerificationToken verificationToken) {
		String url = applicationUrl + "/verifyRegistration?token=" + verificationToken.getToken();

		log.info("Click the link to verify your account : {}", url);
	}
}
