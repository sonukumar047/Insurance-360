package com.example.policy360;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class Policy360Application {

	public static void main(String[] args) {
		SpringApplication.run(Policy360Application.class, args);
	}

}
