package dev.portfolio.iam;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/** Shared Phase 2 issuer/subject mapping; accepts only the authenticated JWT. */
@Component
public class PrincipalResolver {
  private final JdbcTemplate jdbc;

  public PrincipalResolver(JdbcTemplate jdbc) { this.jdbc = jdbc; }

  public UUID resolve(Jwt jwt) {
    List<UUID> ids = jdbc.query(
      "select p.id from principal_identities i join principals p on p.id=i.principal_id " +
      "where i.issuer=? and i.subject=? and p.status='ACTIVE'",
      (rs, n) -> rs.getObject(1, UUID.class), jwt.getIssuer().toString(), jwt.getSubject());
    if (ids.size() != 1) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Identity not provisioned");
    return ids.get(0);
  }
}
