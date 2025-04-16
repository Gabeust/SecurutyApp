package com.gabeuz.security;

import com.gabeuz.security.config.DotenvLoader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		//DotenvLoader.load();
		SpringApplication.run(SecurityApplication.class, args);
	}

}
