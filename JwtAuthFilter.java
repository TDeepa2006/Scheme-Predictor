package com.mindfulmetrics.config;
import com.mindfulmetrics.domain.UserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
/** Role is re-read from the database on every request, so role changes and disabled accounts take effect immediately. */
public class JwtAuthFilter extends OncePerRequestFilter {
  private final JwtService jwt; private final UserRepository users;
  public JwtAuthFilter(JwtService jwt, UserRepository users){ this.jwt=jwt; this.users=users; }
  @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
    String h = req.getHeader("Authorization");
    if (h != null && h.startsWith("Bearer ")) {
      jwt.parse(h.substring(7)).flatMap(users::findById).filter(u -> u.enabled).ifPresent(u ->
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(u.id, null, List.of(new SimpleGrantedAuthority("ROLE_" + u.role.name())))));
    }
    chain.doFilter(req, res);
  }
}
