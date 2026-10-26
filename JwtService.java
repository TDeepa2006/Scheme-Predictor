package com.mindfulmetrics.config;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
@Service
public class JwtService {
  private final SecretKey key; private final long ttlMinutes;
  public JwtService(@Value("${app.jwt.secret}") String secret, @Value("${app.jwt.ttl-minutes}") long ttlMinutes){
    byte[] b = secret.getBytes(StandardCharsets.UTF_8);
    if (b.length < 32) throw new IllegalStateException("JWT_SECRET must be at least 32 bytes");
    this.key = Keys.hmacShaKeyFor(b); this.ttlMinutes = ttlMinutes;
  }
  public String issue(UUID userId){
    long now = System.currentTimeMillis();
    return Jwts.builder().subject(userId.toString()).issuedAt(new Date(now)).expiration(new Date(now + ttlMinutes*60_000)).signWith(key).compact();
  }
  public Optional<UUID> parse(String token){
    try { return Optional.of(UUID.fromString(Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject())); }
    catch (Exception e) { return Optional.empty(); }
  }
}
