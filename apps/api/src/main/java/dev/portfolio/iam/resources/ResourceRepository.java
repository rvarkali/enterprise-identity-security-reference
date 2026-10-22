package dev.portfolio.iam.resources;

import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ResourceRepository {
  public record Project(UUID id, UUID tenantId, String tenantSlug, String name) {}
  public record Document(UUID id, UUID tenantId, String tenantSlug, UUID projectId,
                         String name, String classification) {}

  static final String PROJECT_SQL = """
    select p.id, p.tenant_id, t.slug, p.name
    from projects p join tenants t on t.id = p.tenant_id
    where p.id = ?
    """;
  static final String DOCUMENT_SQL = """
    select d.id, d.tenant_id, t.slug, d.project_id, d.name, d.classification
    from documents d join tenants t on t.id = d.tenant_id
    join projects p on p.id = d.project_id and p.tenant_id = d.tenant_id
    where d.id = ?
    """;
  static final String MEMBERSHIP_SQL = """
    select exists(
      select 1 from tenant_principals tp
      join principals p on p.id = tp.principal_id
      join tenants t on t.id = tp.tenant_id
      where tp.principal_id = ? and tp.tenant_id = ?
        and p.status = 'ACTIVE' and t.status = 'ACTIVE' and tp.status = 'ACTIVE'
    )
    """;

  private final JdbcTemplate jdbc;
  public ResourceRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

  public Optional<Project> findProject(UUID id) {
    return jdbc.query(PROJECT_SQL, (rs, n) -> new Project(rs.getObject("id", UUID.class),
      rs.getObject("tenant_id", UUID.class), rs.getString("slug"), rs.getString("name")), id)
      .stream().findFirst();
  }

  public Optional<Document> findDocument(UUID id) {
    return jdbc.query(DOCUMENT_SQL, (rs, n) -> new Document(rs.getObject("id", UUID.class),
      rs.getObject("tenant_id", UUID.class), rs.getString("slug"), rs.getObject("project_id", UUID.class),
      rs.getString("name"), rs.getString("classification")), id).stream().findFirst();
  }

  // Only ACTIVE eligibility permits revealing resource existence via a 403.
  // AuthorizationService independently rechecks eligibility before OpenFGA.
  public boolean hasMembership(UUID principal, UUID tenantId) {
    return Boolean.TRUE.equals(jdbc.queryForObject(MEMBERSHIP_SQL, Boolean.class, principal, tenantId));
  }
}
