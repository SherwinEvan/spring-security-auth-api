package com.access.auth.entities.listener;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import com.access.auth.entities.UserEntity;
import com.access.auth.event.RegistrationCompleteEvent;
import com.access.auth.signupservice.UserService;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class RegistrationCompleteListener implements ApplicationListener<RegistrationCompleteEvent>{
	
	@Autowired
	private UserService userService;
	
	@Override
	public void onApplicationEvent(RegistrationCompleteEvent event) {
		UserEntity user = event.getUser();
		String token = UUID.randomUUID().toString();
		userService.saveVerificationTokenForUser(token, user);
		
		String url = event.getApplicationUrl() + "/signup/verifyRegistration?token=" + token;
		
		log.info("Click the link to verify your account : {}", url);
	}

}
