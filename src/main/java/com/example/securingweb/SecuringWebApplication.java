package com.example.securingweb;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SecuringWebApplication {

	public static void main(String[] args) throws Throwable {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		System.out.println("Mật khẩu 'user' được mã hóa là: " + encoder.encode("user"));
		System.out.println("Mật khẩu 'admin' được mã hóa là: " + encoder.encode("admin"));
		SpringApplication.run(SecuringWebApplication.class, args);
	}

}
