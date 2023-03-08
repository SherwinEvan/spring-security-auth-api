package com.access.auth.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.access.auth.entities.User;


public interface UserRepo extends JpaRepository<User, Long> {

	User findByEmail(String email);

}
