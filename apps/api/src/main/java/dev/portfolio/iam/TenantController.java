package dev.portfolio.iam;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class TenantController {
  private final JdbcTemplate jdbc;
  private final PrincipalResolver principals;
  TenantController(JdbcTemplate jdbc, PrincipalResolver principals) {
    this.jdbc = jdbc;
    this.principals = principals;
  }

  // All /api/v1 endpoints require a validated JWT; no tenant list is publicly exposed.
  @GetMapping("/me")
  public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
    UUID principal = principals.resolve(jwt);
    List<Map<String, Object>> memberships = jdbc.queryForList(
      "select t.slug, t.display_name from tenant_principals tp join tenants t on t.id=tp.tenant_id " +
      "join principals p on p.id=tp.principal_id where tp.principal_id=? and tp.status='ACTIVE' " +
      "and t.status='ACTIVE' and p.status='ACTIVE' order by t.slug", principal);
    return Map.of("principalId", principal.toString(), "tenants", memberships);
  }

  @GetMapping("/tenants/{slug}")
  public Map<String, Object> tenant(@AuthenticationPrincipal Jwt jwt, @PathVariable String slug) {
    UUID principal = principals.resolve(jwt);
    List<Map<String, Object>> rows = jdbc.queryForList(
      "select t.slug, t.display_name from tenants t join tenant_principals tp on tp.tenant_id=t.id " +
      "join principals p on p.id=tp.principal_id where t.slug=? and tp.principal_id=? " +
      "and tp.status='ACTIVE' and t.status='ACTIVE' and p.status='ACTIVE'", slug, principal);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant access denied");
    return rows.get(0);
  }

}
