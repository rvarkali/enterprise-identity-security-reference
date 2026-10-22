package dev.portfolio.iam.authorization;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;

/**
 * Internal membership + relationship gate, NOT a complete resource authorization boundary.
 * Callers must derive principal from validated identity and tenant/resource from trusted data.
 * ResourceReadService supplies Phase 3.2B PostgreSQL ownership validation for read endpoints.
 */
@Service
public class AuthorizationService {
  public enum ResourceType {
    PROJECT("project"), DOCUMENT("document");
    final String value;
    ResourceType(String value) { this.value = value; }
  }

  public enum Permission {
    CAN_VIEW("can_view"), CAN_EDIT("can_edit"), CAN_DELETE("can_delete");
    final String value;
    Permission(String value) { this.value = value; }
  }

  static final String MEMBERSHIP_SQL = """
    select p.status as principal_status, t.status as tenant_status, tp.status as membership_status
    from tenant_principals tp
    join principals p on p.id = tp.principal_id
    join tenants t on t.id = tp.tenant_id
    where tp.principal_id = ? and t.slug = ?
    """;

  private final JdbcTemplate jdbc;
  private final OpenFgaClient openFga;

  public AuthorizationService(JdbcTemplate jdbc, OpenFgaClient openFga) {
    this.jdbc = jdbc;
    this.openFga = openFga;
  }

  public AuthorizationResult authorize(UUID principal, String tenantSlug, ResourceType type,
                                       String resourceId, Permission permission) {
    if (principal == null || tenantSlug == null || !tenantSlug.matches("[a-z0-9][a-z0-9-]{0,62}")
        || type == null || permission == null || resourceId == null
        || !resourceId.matches("[A-Za-z0-9][A-Za-z0-9_./-]{0,254}")) return INVALID_REQUEST;
    try {
      List<Map<String, Object>> rows = jdbc.queryForList(MEMBERSHIP_SQL, principal, tenantSlug);
      if (rows.size() != 1) return DENY;
      Map<String, Object> row = rows.get(0);
      if (!"ACTIVE".equals(row.get("principal_status"))
          || !"ACTIVE".equals(row.get("tenant_status"))
          || !"ACTIVE".equals(row.get("membership_status"))) return DENY;
    } catch (DataAccessException e) {
      return DATABASE_FAILURE;
    }
    return openFga.check(principal, type.value + ":" + resourceId, permission.value);
  }
}
