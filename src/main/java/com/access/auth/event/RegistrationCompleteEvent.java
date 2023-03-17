package com.access.auth.event;

import org.springframework.context.ApplicationEvent;

import com.access.auth.entities.UserEntity;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationCompleteEvent extends ApplicationEvent {

	private UserEntity user;
	private String applicationUrl;

	public RegistrationCompleteEvent(UserEntity user, String applicationUrl) {
		super(user);
		this.user = user;
		this.applicationUrl = applicationUrl;
	}

	public UserEntity getUser() {
		return this.user;
	}

	public String getApplicationUrl() {
		return applicationUrl;
	}

	public void setApplicationUrl(String applicationUrl) {
		this.applicationUrl = applicationUrl;
	}

	public void setUser(UserEntity user) {
		this.user = user;
	}

}

