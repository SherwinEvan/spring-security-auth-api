package com.access.auth.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.access.auth.entities.VerificationToken;


public interface VerificationTokenRepo extends JpaRepository<VerificationToken, Long> {

	VerificationToken findByToken(String token);

}