package com.mindfulmetrics.config;
import com.mindfulmetrics.domain.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
/** Creates the first HR administrator from environment variables, only if no HR user exists. */
@Component
class BootstrapRunner implements ApplicationRunner {
  private final UserRepository users; private final PasswordEncoder enc; private final String email, password;
  BootstrapRunner(UserRepository users, PasswordEncoder enc, @Value("${app.bootstrap.hr-email}") String email, @Value("${app.bootstrap.hr-password}") String password){
    this.users=users; this.enc=enc; this.email=email; this.password=password; }
  @Override public void run(ApplicationArguments args){
    if (email.isBlank() || password.length() < 12 || users.existsByRole(Role.HR) || users.existsByEmail(email.toLowerCase())) return;
    User u = new User(); u.name = "HR Administrator"; u.email = email.trim().toLowerCase(); u.passwordHash = enc.encode(password); u.role = Role.HR; users.save(u);
  }
}
