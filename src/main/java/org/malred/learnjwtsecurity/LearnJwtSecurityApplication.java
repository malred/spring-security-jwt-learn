package org.malred.learnjwtsecurity;

import org.malred.learnjwtsecurity.domain.Role;
import org.malred.learnjwtsecurity.domain.User;
import org.malred.learnjwtsecurity.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class LearnJwtSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(LearnJwtSecurityApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {

        return args -> {
            userService.saveUser(
                    new User(null, "John Travolta",
                            "john", "1234",
                            new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Will Smith",
                            "will", "1234",
                            new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Jim Carry",
                            "jim", "1234",
                            new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Arnold Schwarzenegger",
                            "arnold", "1234",
                            new ArrayList<>())
            );

            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.addRoleToUser("john", "ROLE_USER");
            userService.addRoleToUser("john", "ROLE_MANAGER");
            userService.addRoleToUser("will", "ROLE_MANAGER");
            userService.addRoleToUser("jim", "ROLE_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_USER");
        };
    }
}
