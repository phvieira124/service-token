package com.br.service_token;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "com.br.service_token")
public class ServiceTokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServiceTokenApplication.class, args);
	}

}
